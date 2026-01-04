import os
import re
import time
from avocado.utils import download
from virttest import data_dir, env_process, error_context, utils_misc, utils_net, utils_netperf


def clean_output(text):
    """
    Clean output by removing null bytes and ANSI escape sequences.
    Handles UTF-16 encoding (null bytes between characters).

    :param text: Raw output text
    :return: Cleaned text
    """
    if not text:
        return ""
    # Handle UTF-16 encoding: remove null bytes between characters
    # This converts UTF-16 to ASCII/UTF-8 by removing every other byte if it's null
    if '\x00' in text:
        # Try to decode as UTF-16 if it looks like UTF-16 (every other byte is null)
        try:
            # If text contains null bytes, try UTF-16LE decode
            if text.count('\x00') > len(text) / 3:  # More than 1/3 are nulls, likely UTF-16
                text = text.decode('utf-16le', errors='ignore')
        except (UnicodeDecodeError, AttributeError):
            # If decode fails, just remove null bytes
            text = text.replace('\u0000', '').replace('\x00', '')
    else:
        # Remove null bytes normally
        text = text.replace('\u0000', '').replace('\x00', '')
    # Remove ANSI escape sequences (console codes)
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    # Remove common escape sequences
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    return text.strip()


@error_context.context_aware
def run(test, params, env):
    """
    Please make sure the guest installed with signed driver
    Verify Secure MOR control feature using Device Guard tool in Windows guest:

    1) Boot up a guest.
    2) Check if Secure Boot is enable.
    3) Download DG_Readiness_Tool and copy to guest.
    4) Enable Device Guard and check the output.
    5) Reboot guest.
    6) Check the result of Device Guard.
    7) Disable Device Guard and shutdown guest.

    :param test: QEMU test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environment.
    """

    def set_powershell_execute_policy(session_obj=None):
        """
        Set PowerShell execution policy using the provided session.
        It is used when creating a new session.

        :param session_obj: The session object to use. If None, uses the outer scope session.
        """
        session_to_use = session_obj if session_obj else session
        error_context.context("Setting PowerShell execution policy.")
        status, output = session_to_use.cmd_status_output(executionPolicy_command)
        if status != 0:
            test.fail("Failed to set PowerShell execution policy: %s" % output)

    def check_secure_boot_enabled():
        """
        Checks if Secure Boot is enabled in the guest.
        """
        error_context.context("Checking if Secure Boot is enabled in the guest")
        output = session.cmd_output(check_cmd)
        if "false" in output.lower():
            test.fail("Secure Boot is not enabled: %s" % output)

    def copy_dg_readiness_tool():
        """
        Copies the Device Guard Readiness tool from the host to the guest VM.
        """
        dgreadiness_host_path = data_dir.get_deps_dir("dgreadiness")
        dst_path = params["dst_path"]
        test.log.info("Copy Device Guard tool to guest.")
        s, o = session.cmd_status_output("mkdir %s" % dst_path)
        if s and "already exists" not in o:
            test.error(
                "Could not create Device Guard directory in "
                "VM '%s', detail: '%s'" % (vm.name, o)
            )
        vm.copy_files_to(dgreadiness_host_path, dst_path)

    def check_vbs_ready():
        """
        Check the status of Virtualization-Based Security (VBS) using the provided
        session.

        :return: True if VBS is enabled, False otherwise.
        """
        status, output = session.cmd_status_output(ready_command)
        if status != 0:
            test.fail("Failed to check VBS status: %s" % output)
        if vbs_ready_info in output:
            test.log.info("VBS is already enabled, and guest boot up successfully")
            return True
        else:
            test.log.info(
                "VBS is not enabled or the expected info was not found in the output"
            )
            return False

    def run_device_guard_tool(cmd, expect_info):
        """
        Executes the Device Guard Readiness Tool command in the guest to enable
        or disable Virtualization-Based Security (VBS).

        :param cmd: The command to enable or disable VBS.
        """
        error_context.context("running device guard readiness tool with %s" % cmd)
        output = session.cmd_output(cmd, 360)
        if expect_info not in output:
            test.fail("Failed to enable VBS: %s" % output)

    def install_wsl2_and_rhel():
        """
        Install WSL2 and start RHEL distribution in Windows VM.
        This function is called after VBS verification (step 5).
        """
        error_context.context("Installing WSL2 and RHEL/Fedora distribution")

        # Enable WSL feature
        test.log.info("Enabling WSL feature...")
        wsl_status, wsl_output = session.cmd_status_output(wsl_enable_cmd, timeout=300)
        test.log.info("WSL command enabled output: %s and status: %s" % (wsl_output, wsl_status))
        # DISM exit codes: 0 = success, 3010 = success (reboot required), others = failure
        if wsl_status == 0:
            test.log.info("WSL feature enabled successfully (status: %d)" % wsl_status)
        elif wsl_status == 3010:
            test.log.info("WSL feature enabled successfully (status: %d) - reboot required" % wsl_status)
        elif "The operation completed successfully" in wsl_output and "100.0%" in wsl_output:
            test.log.info("WSL feature enabled successfully (detected from output, status: %d)" % wsl_status)
        else:
            test.fail("Failed to enable WSL feature: status=%d, output: %s" % (wsl_status, wsl_output))

        # Enable Virtual Machine Platform
        test.log.info("Enabling Virtual Machine Platform...")
        vm_status, vm_output = session.cmd_status_output(vm_platform_cmd, timeout=300)
        test.log.info("VM Platform command enabled output: %s and status: %s" % (vm_output, vm_status))
        if vm_status == 0:
            test.log.info("VM Platform command enabled successfully (status: %d)" % vm_status)
        elif vm_status == 3010:
            test.log.info("VM Platform command enabled successfully (status: %d) - reboot required" % vm_status)
        elif "The operation completed successfully" in vm_output and "100.0%" in vm_output:
            test.log.info("VM Platform command enabled successfully (detected from output, status: %d)" % vm_status)
        else:
            test.fail("Failed to enable VM Platform: status=%d, output: %s" % (vm_status, vm_output))

        # Reboot to apply WSL features (always reboot like test1 does for consistency)
        test.log.info("Rebooting to apply WSL and VM Platform features...")
        vm.reboot(timeout=login_timeout)
        current_session = vm.wait_for_serial_login(timeout=login_timeout)

        # Wait a bit after reboot for features to be fully active
        time.sleep(10)

        # Now use the robust WSL installation code from test1
        # Step 4: Install WSL2
        # Try wsl --update first (can install WSL if not present)
        error_context.context("Installing WSL2", test.log.info)
        test.log.info("Attempting WSL installation using wsl --update...")

        # wsl --update can install WSL if it's not installed
        status, output = current_session.cmd_status_output(wsl_update_cmd, timeout=600)
        output = clean_output(output)
        test.log.debug("wsl --update status: %s, output: %s" % (status, output[:500] if output else "None"))

        # If wsl --update says WSL is not installed, try wsl --install
        if status != 0 or "not installed" in output.lower():
            test.log.info("wsl --update indicates WSL not installed, trying wsl --install...")
            # Try wsl --install with --no-launch to prevent Ubuntu installation prompt
            install_status, install_output = current_session.cmd_status_output(wsl_install_cmd, timeout=600)
            install_output = clean_output(install_output)
            test.log.debug("wsl --install status: %s, output: %s" % (install_status, install_output[:500] if install_output else "None"))

            if install_status == 0 and "not installed" not in install_output.lower():
                status = 0
                output = install_output
            elif "not installed" in install_output.lower() or install_status != 0:
                # If direct install fails, try with elevation
                test.log.info("Direct install failed, trying elevated installation...")
                elevated_status, elevated_output = current_session.cmd_status_output(wsl_install_elevated_cmd, timeout=600)
                elevated_output = clean_output(elevated_output)
                test.log.debug("Elevated install status: %s, output: %s" % (elevated_status, elevated_output[:500] if elevated_output else "None"))
                if elevated_status == 0:
                    status = 0
                    output = elevated_output

        # Verify WSL installation - wait for installation to complete
        test.log.info("Verifying WSL installation...")

        def check_wsl_installed():
            """Check if WSL is installed and ready."""
            verify_status, verify_output = current_session.cmd_status_output(wsl_status_cmd, timeout=30)
            verify_output = clean_output(verify_output)
            return (verify_status == 0 and "not installed" not in verify_output.lower())

        if not utils_misc.wait_for(
            check_wsl_installed,
            timeout=120,  # Total timeout: 2 minutes
            step=20,      # Check every 20 seconds
            text="WSL installation to complete"
        ):
            # Check feature status for debugging
            feature_status, feature_output = current_session.cmd_status_output(wsl_check_cmd, timeout=60)
            feature_output = clean_output(feature_output)
            verify_status, verify_output = current_session.cmd_status_output(wsl_status_cmd, timeout=30)
            verify_output = clean_output(verify_output)
            test.fail("WSL installation failed after reboot and retries. "
                     "WSL status: %s. Feature status: %s" % (verify_output, feature_output))

        test.log.info("WSL installed successfully")

        # Step 5: Reboot after WSL installation to ensure it's fully activated
        test.log.info("Rebooting to activate WSL installation...")
        vm.reboot(timeout=login_timeout)
        current_session = vm.wait_for_serial_login(timeout=login_timeout)

        # Wait a bit after reboot for WSL to be fully ready
        time.sleep(10)

        # Step 6: Create fresh session to pick up environment changes
        error_context.context("Refreshing session after WSL installation", test.log.info)
        wsl_session = vm.wait_for_serial_login(timeout=login_timeout)
        # Wait for WSL to be fully initialized
        time.sleep(30)

        # Step 6.5: Set WSL 2 as default version
        error_context.context("Setting WSL 2 as default version", test.log.info)
        test.log.info("Setting WSL 2 as default version...")
        set_default_status, set_default_output = wsl_session.cmd_status_output(wsl_set_default_version_cmd, timeout=60)
        set_default_output = clean_output(set_default_output)

        if set_default_status != 0:
            test.log.warning("Failed to set WSL 2 as default: %s" % set_default_output)
            # Check if it's already set or if there's a warning we can ignore
            if "already" in set_default_output.lower() or "is already" in set_default_output.lower():
                test.log.info("WSL 2 is already set as default")
            else:
                test.log.warning("Could not set WSL 2 as default, continuing anyway: %s" % set_default_output)
        else:
            test.log.info("WSL 2 set as default version successfully")

        # Step 7: Update WSL2
        error_context.context("Updating WSL2 to latest version", test.log.info)

        # Use sendline to send command and allow interactive handling
        wsl_session.sendline(wsl_update_cmd)

        # Monitor for interactive prompt with timeout (WSL prompt times out in 60s)
        prompt_detected = False
        start_time = time.time()
        timeout = 70
        last_output = ""

        while time.time() - start_time < timeout:
            time.sleep(2)
            current_output = wsl_session.get_output()
            cleaned_output = clean_output(current_output)

            # Check if we see the "Press any key" prompt
            if "Press any key" in cleaned_output and not prompt_detected:
                test.log.info("Handling 'Press any key' prompt during update")
                wsl_session.sendline()  # Send Enter key
                prompt_detected = True
                time.sleep(10)
                last_output = cleaned_output
                continue

            # Check if we have new output indicating progress
            if cleaned_output != last_output:
                last_output = cleaned_output
                # Check for completion indicators
                if ("successfully" in cleaned_output.lower() or
                    "completed" in cleaned_output.lower() or
                    ("not installed" not in cleaned_output.lower() and
                     prompt_detected and "Press any key" not in cleaned_output)):
                    time.sleep(5)
                    break

        # Get the final output using cmd_status_output for clean output
        time.sleep(2)
        try:
            status, output = wsl_session.cmd_status_output(wsl_update_cmd, timeout=30)
            output = clean_output(output)
        except Exception:
            # If command already running, get output from session
            output = clean_output(wsl_session.get_output())
            # Check if WSL is actually installed
            if "not installed" in output.lower():
                status = 1
            elif prompt_detected:
                status = 0
            else:
                status = 1

        # Check for errors
        if status != 0 or ("not installed" in output.lower() and "successfully" not in output.lower()):
            test.fail("Failed to update WSL2: %s" % output)
        test.log.info("WSL2 updated successfully")

        # Step 8: List WSL distributions
        error_context.context("Listing WSL distributions", test.log.info)

        def list_wsl_distributions():
            """List WSL distributions and return (success, output)."""
            try:
                status, output = wsl_session.cmd_status_output(wsl_list_cmd, timeout=100)
                output = clean_output(output)
                # Check if we have the "Press any key" prompt or "not installed" error
                if "Press any key" in output or "not installed" in output.lower():
                    return False, output
                return (status == 0), output
            except Exception as e:
                test.log.warning("Error executing WSL list command: %s" % str(e))
                # Fallback: use sendline and monitor
                wsl_session.sendline(wsl_list_cmd)

                # Monitor for interactive prompt with timeout
                prompt_detected = False
                start_time = time.time()
                timeout = 70
                last_output = ""

                while time.time() - start_time < timeout:
                    time.sleep(2)
                    current_output = wsl_session.get_output()
                    cleaned_output = clean_output(current_output)

                    # Check if we see the "Press any key" prompt
                    if "Press any key" in cleaned_output and not prompt_detected:
                        test.log.info("Handling 'Press any key' prompt during list")
                        wsl_session.sendline()
                        prompt_detected = True
                        time.sleep(10)
                        last_output = cleaned_output
                        continue

                    # Check if command has completed
                    if cleaned_output != last_output:
                        last_output = cleaned_output
                        if prompt_detected or "Press any key" not in cleaned_output:
                            time.sleep(3)
                            break

                # Get final output
                time.sleep(2)
                try:
                    status, output = wsl_session.cmd_status_output(wsl_list_cmd, timeout=30)
                    output = clean_output(output)
                    if "Press any key" in output or "not installed" in output.lower():
                        return False, output
                    return (status == 0), output
                except Exception:
                    output = clean_output(wsl_session.get_output())
                    if "not installed" in output.lower():
                        return False, output
                    return True, output

        # Use wait_for to retry listing with proper error handling
        def check_wsl_list_success():
            """Check if WSL list command succeeds."""
            success, output = list_wsl_distributions()
            if success:
                test.log.info("WSL distributions list:\n%s" % output)
            return success

        if not utils_misc.wait_for(
            check_wsl_list_success,
            timeout=90,  # Total timeout: 90 seconds
            step=20,      # Check every 20 seconds
            text="WSL list command to succeed"
        ):
            # Final attempt to get error details
            _, final_output = list_wsl_distributions()
            test.fail("Failed to list WSL distributions: %s" % clean_output(final_output))

        # Get the list output to check for RHEL
        _, list_output = list_wsl_distributions()
        list_output = clean_output(list_output)

        # Step 9: Install RHEL if available, otherwise install Fedora
        error_context.context("Installing WSL distribution", test.log.info)

        # Check if RHEL is in the list (case-insensitive search for various RHEL names)
        list_output_upper = list_output.upper()
        rhel_found = (
            "RHEL" in list_output_upper or
            "RED HAT" in list_output_upper or
            "REDHAT" in list_output_upper or
            "RED HAT ENTERPRISE" in list_output_upper
        )

        if rhel_found:
            test.log.info("RHEL found in available distributions, installing RHEL...")
            install_dist_cmd = wsl_install_rhel_cmd
            dist_name = "RHEL"
        else:
            test.log.info("RHEL not found in available distributions, installing Fedora...")
            # Verify Fedora is available before attempting installation
            if "FEDORA" in list_output_upper:
                # Extract the actual Fedora distribution name from the list
                # Look for lines containing "Fedora" and extract the NAME column
                fedora_dist_name = None
                for line in list_output.split('\n'):
                    line_upper = line.upper()
                    if "FEDORA" in line_upper and not line_upper.startswith("NAME") and not line_upper.startswith("---"):
                        # Extract the first word (distribution name) from the line
                        parts = line.strip().split()
                        if parts:
                            fedora_dist_name = parts[0]
                            test.log.info("Found Fedora distribution: %s" % fedora_dist_name)
                            break

                if fedora_dist_name:
                    # Use the actual distribution name in the install command
                    # Replace the distribution name in the command (e.g., "FedoraLinux-43" -> actual name)
                    # The CFG has "FedoraLinux-43", so we need to find and replace it
                    if "FedoraLinux" in wsl_install_fedora_cmd:
                        # Extract the distribution name from the command and replace it
                        install_dist_cmd = re.sub(r'FedoraLinux[-\d]+', fedora_dist_name, wsl_install_fedora_cmd)
                    else:
                        # Fallback: try replacing "Fedora" if present
                        install_dist_cmd = wsl_install_fedora_cmd.replace("Fedora", fedora_dist_name)
                    dist_name = fedora_dist_name  # Set dist_name for use in logging
                    actual_dist_name = fedora_dist_name  # Use actual name from the start
                else:
                    # Fallback to generic "Fedora" if we can't parse it
                    install_dist_cmd = wsl_install_fedora_cmd
                    dist_name = "Fedora"
            else:
                test.fail("Neither RHEL nor Fedora found in available distributions. Available: %s" % list_output)

        # Install the distribution
        test.log.info("Installing %s distribution..." % dist_name)

        # Use sendline to handle interactive prompts (username creation)
        wsl_session.sendline(install_dist_cmd)

        # Monitor for interactive prompt with timeout
        username_prompt_detected = False
        installation_complete = False
        start_time = time.time()
        timeout = 600  # 10 minutes timeout
        last_output = ""

        while time.time() - start_time < timeout:
            time.sleep(2)
            current_output = wsl_session.get_output()
            cleaned_output = clean_output(current_output)

            # Check if we see the informational message about creating a user account
            # When this message appears, the command is waiting for username input
            # The actual prompt text may not always be visible in the output
            info_message_seen = ("create a default user account" in cleaned_output.lower() and
                                "wslusers" in cleaned_output.lower())

            # Check if we see an explicit username prompt
            # The prompt can appear in different formats:
            # - "Enter new UNIX username:" (actual prompt)
            # - "New UNIX username:" (alternative prompt format)
            username_prompt_seen = ("enter new unix username" in cleaned_output.lower() or
                                   "new unix username" in cleaned_output.lower() or
                                   (":" in cleaned_output and "username" in cleaned_output.lower() and
                                    "unix" in cleaned_output.lower()))

            # Send username when we detect the info message or explicit prompt
            # The info message indicates the command is waiting for input
            if (info_message_seen or username_prompt_seen) and not username_prompt_detected:
                test.log.info("Detected username prompt, sending default username: %s" % wsl_default_username)
                wsl_session.sendline(wsl_default_username)
                username_prompt_detected = True
                time.sleep(5)
                last_output = cleaned_output
                continue

            # Check if we see password prompt (some distributions may ask for password)
            if ("password" in cleaned_output.lower() and "new unix" in cleaned_output.lower() and
                username_prompt_detected and not installation_complete):
                test.log.info("Detected password prompt, sending default password")
                wsl_session.sendline(wsl_default_password)
                time.sleep(5)
                last_output = cleaned_output
                continue

            # Check if distribution already exists (from previous test run)
            already_exists_indicators = (
                "already exists" in cleaned_output.lower() or
                "error_already_exists" in cleaned_output.lower() or
                "distribution with the supplied name already exists" in cleaned_output.lower() or
                "wsl/installdistro/error_already_exists" in cleaned_output.lower()
            )

            if already_exists_indicators and not installation_complete:
                test.log.info("Distribution %s already exists from previous installation, using existing distribution" % dist_name)
                installation_complete = True
                # Wait a bit to ensure the command has finished
                time.sleep(5)
                # Verify the distribution actually exists in the list
                try:
                    verify_cmd = 'wsl --list --verbose'
                    verify_status, verify_output = wsl_session.cmd_status_output(verify_cmd, timeout=30)
                    verify_output = clean_output(verify_output)
                    # Check if distribution is in the list
                    if dist_name.upper() in verify_output.upper():
                        test.log.info("Verified that %s distribution exists in WSL list" % dist_name)
                    else:
                        test.log.warning("Distribution %s not found in WSL list, but 'already exists' error was detected" % dist_name)
                except Exception as e:
                    test.log.warning("Could not verify distribution existence: %s" % str(e))
                break

            # Check if installation is complete
            if cleaned_output != last_output:
                last_output = cleaned_output
                # Check for completion indicators
                completion_indicators = (
                    "installed successfully" in cleaned_output.lower() or
                    "installation completed" in cleaned_output.lower() or
                    "is already installed" in cleaned_output.lower() or
                    "installation finished" in cleaned_output.lower() or
                    "already exists" in cleaned_output.lower() or
                    "error_already_exists" in cleaned_output.lower()
                )

                # If we've sent the username and the prompt messages are gone,
                # and we see the command prompt pattern, installation likely completed
                prompt_gone = (
                    username_prompt_detected and
                    "wslusers" not in cleaned_output.lower() and
                    "create a default user" not in cleaned_output.lower() and
                    "enter new unix username" not in cleaned_output.lower() and
                    "new unix username" not in cleaned_output.lower()
                )

                # Check if we're back at Windows command prompt (indicates command finished)
                # Look for Windows path pattern like C:\> or similar
                back_at_prompt = re.search(r'[A-Z]:\\.*>', cleaned_output)

                if completion_indicators or (prompt_gone and back_at_prompt):
                    # Wait a bit more to ensure installation is fully complete
                    time.sleep(10)
                    installation_complete = True
                    break

        # Get the final output
        time.sleep(2)
        actual_dist_name = dist_name  # Default to dist_name, will be updated if we find the actual name
        try:
            # Try to get status by checking if distribution is installed
            check_cmd = 'wsl --list --verbose'
            status, output = wsl_session.cmd_status_output(check_cmd, timeout=30)
            output = clean_output(output)

            # Parse the output to find the actual distribution name
            # WSL list output format: "NAME    STATE    VERSION"
            # We need to find a distribution that matches dist_name (case-insensitive, partial match)
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                if not line or line.startswith('NAME') or line.startswith('---'):
                    continue
                # Extract the distribution name (first column)
                parts = line.split()
                if parts:
                    installed_dist = parts[0]
                    # Check if this distribution matches our dist_name (case-insensitive, partial match)
                    if dist_name.upper() in installed_dist.upper() or installed_dist.upper() in dist_name.upper():
                        actual_dist_name = installed_dist
                        test.log.info("Found installed distribution name: %s (searched for: %s)" % (actual_dist_name, dist_name))
                        break

            # Check if the distribution appears in the list
            dist_installed = dist_name in output or dist_name.upper() in output.upper() or actual_dist_name != dist_name

            if dist_installed:
                install_status = 0
                install_output = "Distribution installed successfully"
            elif installation_complete:
                install_status = 0
                install_output = clean_output(wsl_session.get_output())
            else:
                install_status = 1
                install_output = clean_output(wsl_session.get_output())
        except Exception as e:
            test.log.warning("Error checking installation status: %s" % str(e))
            install_output = clean_output(wsl_session.get_output())
            if installation_complete or username_prompt_detected:
                install_status = 0
            else:
                install_status = 1

        install_output = clean_output(install_output)

        # Check for "already exists" error in the final output as well
        already_exists_in_output = (
            "already exists" in install_output.lower() or
            "error_already_exists" in install_output.lower() or
            "distribution with the supplied name already exists" in install_output.lower() or
            "wsl/installdistro/error_already_exists" in install_output.lower()
        )

        if install_status != 0:
            test.log.warning("Installation command returned non-zero status: %s" % install_output)
            # Check if it's already installed or already exists
            if ("already installed" in install_output.lower() or
                "is already installed" in install_output.lower() or
                already_exists_in_output):
                test.log.info("%s is already installed/exists, proceeding with existing distribution" % dist_name)
                install_status = 0  # Treat as success since distribution exists
            else:
                test.fail("Failed to install %s distribution: %s" % (dist_name, install_output))

        if install_status == 0:
            if already_exists_in_output:
                test.log.info("%s distribution already exists (actual name: %s), using existing installation" % (dist_name, actual_dist_name))
            else:
                test.log.info("%s distribution installed successfully (actual name: %s)" % (dist_name, actual_dist_name))

        # Step 10: Test the installed distribution by running uname -a
        error_context.context("Testing installed WSL distribution", test.log.info)
        test.log.info("Running uname -a in %s distribution (actual name: %s)..." % (dist_name, actual_dist_name))

        # Replace RHEL in the command with the actual distribution name
        uname_cmd = wsl_uname_cmd.replace("RHEL", actual_dist_name)

        # Ensure the command uses -- to properly separate WSL options from the command
        # WSL requires -- to separate options from the command to execute
        if " -- " not in uname_cmd and ' --' not in uname_cmd:
            # Check if command has quotes, if so replace the pattern, otherwise add -- before the command
            if '"' in uname_cmd:
                # Pattern: wsl -d DISTRO "command" -> wsl -d DISTRO -- "command"
                uname_cmd = uname_cmd.replace('"', ' -- "', 1)
            else:
                # Pattern: wsl -d DISTRO command -> wsl -d DISTRO -- command
                # Find where the distribution name ends and add -- before the command
                parts = uname_cmd.split(None, 3)  # Split into max 4 parts: wsl, -d, DISTRO, command
                if len(parts) >= 4:
                    uname_cmd = ' '.join(parts[:3]) + ' -- ' + parts[3]
                elif len(parts) == 3:
                    # No command part, this shouldn't happen but handle it
                    uname_cmd = uname_cmd + ' -- uname -a'

        test.log.debug("Executing WSL command: %s" % uname_cmd)
        uname_status, uname_output = wsl_session.cmd_status_output(uname_cmd, timeout=120)
        uname_output = clean_output(uname_output)

        if uname_status != 0:
            test.fail("Failed to run uname -a in %s distribution (actual name: %s): %s" % (dist_name, actual_dist_name, uname_output))
        else:
            test.log.info("uname -a output from %s (actual name: %s):\n%s" % (dist_name, actual_dist_name, uname_output))
            # Verify we got meaningful output
            if not uname_output or len(uname_output.strip()) < 10:
                test.fail("uname -a returned empty or invalid output: %s" % uname_output)

        # Return the wsl_session and dist_name (keep wsl_session open for later use)
        return wsl_session, actual_dist_name

    def install_mysql_service():
        """
        Install and start MySQL service in Windows VM.
        Downloads installer at runtime if URL is provided.
        """
        error_context.context("Installing MySQL service in guest")

        # Check if installed
        installed = session.cmd_status(mysql_check_installed_cmd) == 0

        if not installed:
            # Install MySQL
            error_context.context("Installing MySQL Server", test.log.info)

            # Check if we should download at runtime
            download_url = params.get("mysql_download_url")

            if download_url:
                # RUNTIME DOWNLOAD PATTERN
                tmp_dir = data_dir.get_tmp_dir()
                pkg_md5sum = params.get("mysql_pkg_md5sum", "")

                error_context.context("Downloading MySQL installer", test.log.info)
                pkg_name = os.path.basename(download_url)
                pkg_path = os.path.join(tmp_dir, pkg_name)

                test.log.info("Downloading from: %s" % download_url)
                test.log.info("Download destination: %s" % pkg_path)

                # Download to host
                if pkg_md5sum:
                    download.get_file(download_url, pkg_path, hash_expected=pkg_md5sum)
                else:
                    download.get_file(download_url, pkg_path)

                test.log.info("Download completed, copying to guest...")

                # Copy to guest
                dst = r"c:\\"
                vm.copy_files_to(pkg_path, dst)

                # Update install command to use downloaded file
                install_cmd = mysql_install_cmd.replace("DRIVE:\\", dst)
                test.log.info("Using downloaded installer: %s" % install_cmd)
            else:
                # Use existing pattern (from winutils)
                test.log.info("Using installer from winutils")
                dst = r"%s:\\" % utils_misc.get_winutils_vol(session)
                install_cmd = re.sub(r"DRIVE:\\+", dst, mysql_install_cmd)

            # Install
            test.log.info("Installing MySQL (this may take 3-5 minutes)...")
            status, output = session.cmd_status_output(install_cmd, timeout=600)
            if status != 0:
                test.fail("MySQL installation failed: %s" % output)

            test.log.info("MySQL installation completed successfully")
            test.log.info("Waiting 30 seconds for post-install tasks...")
            time.sleep(30)

            # Verify
            if session.cmd_status(mysql_check_installed_cmd) != 0:
                test.fail("MySQL installation verification failed")

        # Check service status
        error_context.context("Checking MySQL service status", test.log.info)
        status, service_output = session.cmd_status_output(mysql_check_service_cmd)

        if status != 0:
            test.fail("MySQL service not found: %s" % service_output)

        # Start if stopped
        if "STOPPED" in service_output.upper():
            error_context.context("Starting MySQL service", test.log.info)
            status, start_output = session.cmd_status_output(
                mysql_start_service_cmd, timeout=60
            )
            if status != 0:
                test.fail("Failed to start MySQL: %s" % start_output)
            time.sleep(10)

        # Verify running
        status, verify_output = session.cmd_status_output(mysql_check_service_cmd)
        if "RUNNING" not in verify_output.upper():
            test.fail("MySQL service not running")

        test.log.info("MySQL service installed and running successfully")
        return session

    def run_netperf_and_stress_test(distro_name):
        """
        Run netperf from Windows guest to host and stress test concurrently.
        Verifies VM stability, MySQL service, and all applications under load.

        Steps:
        1. Start netserver on host
        2. Start netperf client in Windows guest
        3. Start stress in WSL2 (already installed from Step 3)
        4. Monitor both processes for test_duration seconds
        5. Verify VM stability and service health throughout

        :param distro_name: Name of the WSL distribution (RHEL or Fedora)
        """
        error_context.context("Running netperf and stress test concurrently", test.log.info)

        # Determine package manager based on distribution
        distro_name_upper = distro_name.upper()
        if "RHEL" in distro_name_upper or "REDHAT" in distro_name_upper or "RED HAT" in distro_name_upper:
            pkg_manager = "yum"
        elif "FEDORA" in distro_name_upper:
            pkg_manager = "dnf"
        else:
            # Default to yum if unknown
            pkg_manager = "yum"
            test.log.warning("Unknown distribution '%s', defaulting to yum package manager" % distro_name)

        # Get host IP
        host_ip = utils_net.get_host_ip_address(params)
        test.log.info(f"Host IP for netperf server: {host_ip}")

        # Setup paths for netperf binaries
        netperf_server_src = os.path.join(
            data_dir.get_deps_dir("netperf"),
            netperf_link
        )
        netperf_client_src = os.path.join(
            data_dir.get_deps_dir("netperf"),
            netperf_client_link_win
        )

        # Initialize netperf server (on host) and client (in Windows guest)
        n_server = utils_netperf.NetperfServer(
            host_ip,
            server_path,
            netperf_source=netperf_server_src,
            password=hostpassword
        )

        n_client = utils_netperf.NetperfClient(
            vm.get_address(),
            client_path,
            netperf_source=netperf_client_src,
            client="ssh",
            port="22",
            username=params["username"],
            password=params["password"],
            prompt=params.get("shell_prompt", r"^root@.*[\#\$]\s*$|#"),
            linesep=params.get("shell_linesep", "\n").encode().decode("unicode_escape"),
            status_test_command=params.get("status_test_command", "echo %errorlevel%")
        )

        try:
            # Step 1: Start netserver on host
            error_context.context("Starting netserver on host", test.log.info)
            n_server.start()
            test.log.info("Netserver started on host successfully")

            # Step 2: Start netperf client in Windows guest (background)
            test_option = f"-l {netperf_test_duration} -t {test_protocol}"
            error_context.context(
                f"Starting netperf client in guest with options: {test_option}",
                test.log.info
            )
            n_client.bg_start(host_ip, test_option, "1", "")

            # Wait for netperf to actually start
            if not utils_misc.wait_for(
                n_client.is_netperf_running,
                timeout=30,
                first=0,
                step=3,
                text="Waiting for netperf client to start"
            ):
                test.error("Failed to start netperf client in guest")

            test.log.info("Netperf client started successfully in guest")

            # Step 3: Install stress in WSL2 if not already installed
            error_context.context("Preparing stress tool in WSL2", test.log.info)
            install_check = session.cmd_status("wsl -d %s -- which stress" % distro_name)
            if install_check != 0:
                test.log.info("Installing stress in WSL2 %s distribution..." % distro_name)
                install_status = session.cmd_status(
                    "wsl -d %s -- sudo %s install -y stress" % (distro_name, pkg_manager),
                    timeout=300
                )
                if install_status != 0:
                    test.log.warning("Stress installation had issues, attempting to continue...")
            else:
                test.log.info("Stress already installed in WSL2")

            # Step 4: Start stress in background via WSL2
            stress_cmd = (
                f'start /b wsl -d {distro_name} -- stress '
                f'--cpu {stress_cpu} '
                f'--vm {stress_vm} '
                f'--vm-bytes {stress_vm_bytes} '
                f'--timeout {stress_timeout}'
            )
            error_context.context(
                f"Starting stress in WSL2 with command: {stress_cmd}",
                test.log.info
            )
            session.sendline(stress_cmd)
            time.sleep(5)  # Give stress time to start

            # Verify stress started
            stress_check = session.cmd_status("wsl -d %s -- pgrep stress" % distro_name)
            if stress_check != 0:
                test.error("Failed to start stress process in WSL2")

            test.log.info("Stress test started successfully in WSL2")
            test.log.info("="*60)
            test.log.info("CONCURRENT WORKLOAD RUNNING:")
            test.log.info(f"  - Netperf: Guest → Host for {netperf_test_duration}s")
            test.log.info(f"  - Stress: {stress_cpu} CPU, {stress_vm} VM worker, {stress_vm_bytes} memory")
            test.log.info("="*60)

            # Step 5: Monitor concurrent execution
            start_time = time.time()
            max_duration = netperf_test_duration + deviation_time
            check_interval = 10

            while time.time() - start_time < max_duration:
                elapsed = time.time() - start_time

                # Check 1: Netperf status
                netperf_running = n_client.is_netperf_running()
                if not netperf_running and elapsed < netperf_test_duration - 10:
                    test.fail(f"Netperf terminated unexpectedly at {elapsed:.0f}s")

                # Check 2: Stress status (it's OK if it completes)
                stress_running = session.cmd_status("wsl -d %s -- pgrep stress" % distro_name) == 0

                # Check 3: VM is alive
                if not vm.is_alive():
                    test.fail(f"VM crashed during concurrent test at {elapsed:.0f}s")

                # Check 4: MySQL service still running
                mysql_status = session.cmd_status(mysql_check_service_cmd)
                if mysql_status != 0:
                    test.fail(f"MySQL service stopped during test at {elapsed:.0f}s")

                # Check 5: WSL2 still responsive
                wsl_check = session.cmd_status("wsl -d %s -- echo test" % distro_name, timeout=10)
                if wsl_check != 0:
                    test.fail(f"WSL2 became unresponsive at {elapsed:.0f}s")

                # Check 6: Guest session responsive
                try:
                    session.cmd("echo alive", timeout=15)
                except Exception as e:
                    test.fail(f"Guest session became unresponsive at {elapsed:.0f}s: {e}")

                # Log comprehensive status
                status_msg = (
                    f"[{elapsed:>6.0f}s/{max_duration}s] "
                    f"Netperf: {'✓ Running' if netperf_running else '✗ Stopped':>12} | "
                    f"Stress: {'✓ Running' if stress_running else '✗ Stopped':>12} | "
                    f"VM: ✓ Alive | MySQL: ✓ Running | WSL2: ✓ Responsive"
                )
                test.log.info(status_msg)

                time.sleep(check_interval)

            # Step 6: Verify netperf completed cleanly (not hung)
            if n_client.is_netperf_running():
                test.fail("Netperf still running after timeout, may have hung")

            # Success!
            test.log.info("="*60)
            test.log.info("✅ CONCURRENT TEST COMPLETED SUCCESSFULLY!")
            test.log.info(f"✅ Netperf ran for {netperf_test_duration}s without issues")
            test.log.info(f"✅ Stress ran for {stress_timeout}s under load")
            test.log.info("✅ VM remained stable throughout test")
            test.log.info("✅ All services (MySQL, WSL2) operational")
            test.log.info("✅ No crashes, hangs, or service failures detected")
            test.log.info("="*60)

        finally:
            # Cleanup: Always cleanup even on failure
            error_context.context("Cleaning up netperf and stress processes", test.log.info)

            if n_server:
                if n_server.is_server_running():
                    n_server.stop()
                n_server.cleanup(True)
                test.log.info("Netserver stopped and cleaned up")

            if n_client:
                if n_client.is_netperf_running():
                    n_client.stop()
                n_client.cleanup(True)
                test.log.info("Netperf client stopped and cleaned up")

            # Kill any remaining stress processes
            session.cmd("wsl -d %s -- pkill -9 stress" % distro_name, ignore_all_errors=True)
            test.log.info("Stress processes cleaned up")

    login_timeout = int(params.get("login_timeout", 360))
    params["ovmf_vars_filename"] = "OVMF_VARS.secboot.fd"
    params["clone_master"] = "yes"
    params["master_images_clone"] = "image1"
    params["remove_image_image1"] = "yes"
    params["start_vm"] = "yes"
    env_process.preprocess_vm(test, params, env, params["main_vm"])
    vm = env.get_vm(params["main_vm"])
    session = vm.wait_for_serial_login(timeout=login_timeout)

    check_cmd = params["check_secure_boot_enabled_cmd"]
    dgreadiness_path_command = params["dgreadiness_path_cmd"]
    executionPolicy_command = params["set_ps_policy_cmd"]
    enable_command = params["vbs_enable_cmd"]
    disable_command = params["vbs_disable_cmd"]
    ready_command = params["vbs_ready_cmd"]
    vbs_ready_info = params["vbs_ready_info"]
    vbs_enable_info = params["vbs_enable_info"]
    vbs_disable_info = params["vbs_disable_info"]
    wsl_enable_cmd = params["wsl_enable_cmd"]
    vm_platform_cmd = params["vm_platform_cmd"]
    # Use .get() for optional parameters that may not be in CFG
    rhel_install_cmd = params.get("rhel_install_cmd", "wsl --install -d RHEL")
    wsl_install_cmd = params["wsl_install_cmd"]
    wsl_list_cmd = params["wsl_list_cmd"]
    wsl_update_cmd = params["wsl_update_cmd"]
    fedora_install_cmd = params.get("fedora_install_cmd", "wsl --install -d Fedora")
    # Additional WSL parameters needed for robust installation
    wsl_install_elevated_cmd = params.get("wsl_install_elevated_cmd", "")
    wsl_status_cmd = params.get("wsl_status_cmd", "wsl --status")
    wsl_check_cmd = params.get("wsl_check_cmd", "")
    wsl_set_default_cmd = params.get("wsl_set_default_cmd")
    # Define wsl_set_default_version_cmd from wsl_set_default_cmd
    wsl_set_default_version_cmd = params.get("wsl_set_default_version_cmd", wsl_set_default_cmd)
    wsl_install_rhel_cmd = params.get("wsl_install_rhel_cmd", rhel_install_cmd)
    wsl_install_fedora_cmd = params.get("wsl_install_fedora_cmd", fedora_install_cmd)
    wsl_uname_cmd = params.get("wsl_uname_cmd", "")
    wsl_default_username = params.get("wsl_default_username", "testuser")
    wsl_default_password = params.get("wsl_default_password", "testpass123")
    # Added MySQL params here
    mysql_install_cmd = params["mysql_install_cmd"]
    mysql_check_installed_cmd = params["mysql_check_installed_cmd"]
    mysql_start_service_cmd = params["mysql_start_service_cmd"]
    mysql_check_service_cmd = params["mysql_check_service_cmd"]
    # Netperf and stress test params
    hostpassword = params.get("hostpassword", "redhat")
    netperf_link = params.get("netperf_link", "netperf-2.7.1.tar.bz2")
    netperf_client_link_win = params.get("netperf_client_link_win", "netperf.exe")
    netperf_test_duration = int(params.get("netperf_test_duration", 180))
    deviation_time = int(params.get("deviation_time", 20))
    server_path = params.get("server_path", "/var/tmp/")
    client_path = params.get("client_path", "c:\\")
    test_protocol = params.get("test_protocol", "TCP_STREAM")
    stress_timeout = int(params.get("stress_timeout", 180))
    stress_cpu = int(params.get("stress_cpu", 1))
    stress_vm = int(params.get("stress_vm", 1))
    stress_vm_bytes = params.get("stress_vm_bytes", "20M")

    try:
        check_secure_boot_enabled()
        copy_dg_readiness_tool()
        set_powershell_execute_policy()
        session.cmd(dgreadiness_path_command)
        if not check_vbs_ready():
            run_device_guard_tool(enable_command, vbs_enable_info)
            vm.reboot(timeout=login_timeout)
            session = vm.wait_for_serial_login(timeout=login_timeout)
            session.cmd(dgreadiness_path_command)
            set_powershell_execute_policy(session)
            if not check_vbs_ready():
                test.fail("VBS is not enabled after reboot.")

        wsl_session, wsl_distro_name = install_wsl2_and_rhel()

        session = install_mysql_service()

        # Step 5: Run netperf and stress test concurrently
        run_netperf_and_stress_test(wsl_distro_name)

        run_device_guard_tool(disable_command, vbs_disable_info)
    except Exception as e:
        test.fail(f"Test failed: {e}")
    else:
        test.log.info("Test completed successfully.")
    finally:
        if vm.is_alive():
            vm.destroy()
        if session:
            session.close()
        if 'wsl_session' in locals() and wsl_session:
            wsl_session.close()

