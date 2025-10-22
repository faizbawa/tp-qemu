import os
import re
import time
from avocado.utils import download
from virttest import data_dir, env_process, error_context, utils_misc, utils_net, utils_netperf


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

    def set_powershell_execute_policy():
        """
        Set PowerShell execution policy using the provided session.
        It is used when creating a new session.

        :param cmd: The PowerShell command to set execution policy.
        """
        error_context.context("Setting PowerShell execution policy.")
        status, output = session.cmd_status_output(executionPolicy_command)
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
        error_context.context("Installing WSL2 and RHEL distribution")

        # Enable WSL feature
        test.log.info("Enabling WSL feature...")
        status, output = session.cmd_status_output(wsl_enable_cmd, timeout=300)
        if status != 0:
            test.fail("Failed to enable WSL feature: %s" % output)

        # Enable Virtual Machine Platform
        test.log.info("Enabling Virtual Machine Platform...")
        status, output = session.cmd_status_output(vm_platform_cmd, timeout=300)
        if status != 0:
            test.fail("Failed to enable VM Platform: %s" % output)

        # Reboot to apply WSL2 features
        test.log.info("Rebooting to apply WSL2 features...")
        vm.reboot(timeout=login_timeout)
        new_session = vm.wait_for_serial_login(timeout=login_timeout)
        set_powershell_execute_policy()
        new_session.cmd(dgreadiness_path_command)

        # Set WSL2 as default
        test.log.info("Setting WSL2 as default version...")
        status, output = new_session.cmd_status_output(wsl_set_default_cmd, timeout=60)
        if status != 0:
            test.fail("Failed to set WSL2 default: %s" % output)

        # Install RHEL distribution
        test.log.info("Installing RHEL distribution...")
        status, output = new_session.cmd_status_output(rhel_install_cmd, timeout=600)
        if status != 0:
            test.fail("Failed to install RHEL: %s" % output)

        # Verify WSL2 and RHEL installation
        test.log.info("Verifying WSL2 and RHEL...")
        status, output = new_session.cmd_status_output(wsl_list_cmd, timeout=60)
        if status != 0:
            test.fail("Failed to list WSL distributions: %s" % output)
        if rhel_distro_name not in output:
            test.fail("RHEL distribution not found: %s" % output)

        # Test RHEL functionality
        test.log.info("Testing RHEL in WSL2...")
        status, output = new_session.cmd_status_output(rhel_test_cmd, timeout=120)
        if status != 0:
            test.fail("RHEL test failed: %s" % output)
        test.log.info("WSL2 with RHEL installed and verified successfully")
        return new_session
    
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

    def run_netperf_and_stress_test():
        """
        Run netperf from Windows guest to host and stress test concurrently.
        Verifies VM stability, MySQL service, and all applications under load.

        Steps:
        1. Start netserver on host
        2. Start netperf client in Windows guest
        3. Start stress in WSL2 (already installed from Step 3)
        4. Monitor both processes for test_duration seconds
        5. Verify VM stability and service health throughout
        """
        error_context.context("Running netperf and stress test concurrently", test.log.info)

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
            install_check = session.cmd_status("wsl -d RHEL -- which stress")
            if install_check != 0:
                test.log.info("Installing stress in WSL2 RHEL distribution...")
                install_status = session.cmd_status(
                    "wsl -d RHEL -- sudo yum install -y stress",
                    timeout=300
                )
                if install_status != 0:
                    test.log.warning("Stress installation had issues, attempting to continue...")
            else:
                test.log.info("Stress already installed in WSL2")

            # Step 4: Start stress in background via WSL2
            stress_cmd = (
                f'start /b wsl -d RHEL -- stress '
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
            stress_check = session.cmd_status("wsl -d RHEL -- pgrep stress")
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
                stress_running = session.cmd_status("wsl -d RHEL -- pgrep stress") == 0

                # Check 3: VM is alive
                if not vm.is_alive():
                    test.fail(f"VM crashed during concurrent test at {elapsed:.0f}s")

                # Check 4: MySQL service still running
                mysql_status = session.cmd_status(mysql_check_service_cmd)
                if mysql_status != 0:
                    test.fail(f"MySQL service stopped during test at {elapsed:.0f}s")

                # Check 5: WSL2 still responsive
                wsl_check = session.cmd_status("wsl -d RHEL -- echo test", timeout=10)
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
            session.cmd("wsl -d RHEL -- pkill -9 stress", ignore_all_errors=True)
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
    wsl_set_default_cmd = params["wsl_set_default_cmd"]
    rhel_install_cmd = params["rhel_install_cmd"]
    wsl_list_cmd = params["wsl_list_cmd"]
    rhel_distro_name = params["rhel_distro_name"]
    rhel_test_cmd = params["rhel_test_cmd"]
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
            set_powershell_execute_policy()
            if not check_vbs_ready():
                test.fail("VBS is not enabled after reboot.")

        session = install_wsl2_and_rhel()

        session = install_mysql_service()

        # Step 5: Run netperf and stress test concurrently
        run_netperf_and_stress_test()

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
