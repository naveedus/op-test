#!/usr/bin/env python3
# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: op-test-framework/testcases/OpTestKernelDumpSANAnalysis.py $
#
# OpenPOWER Automated Test Project
#
# Contributors Listed Below - COPYRIGHT 2024
# [+] International Business Machines Corp.
# [+] Naveed AUS <naveedaus@in.ibm.com> - Assisted with AI tools
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# IBM_PROLOG_END_TAG

"""
OpTestKernelDumpSANAnalysis
----------------------------

Enhanced test case for kernel crash dump to SAN disk with comprehensive crash analysis.

Supports both PowerNV (bare-metal) and PowerVM LPAR environments.

This test implements the following workflow:
1. Format a SAN disk LUN with EXT4 filesystem
2. Mount the formatted LUN to a designated mount point and add to fstab
3. Configure kdump to use the SAN mount point as dump target
4. Trigger a kernel crash to generate vmcore dump (supports HMC dumprestart for LPAR)
5. Wait for system to complete dump and reboot
6. Verify dump file was successfully written to SAN disk
7. Perform crash analysis using crash utility tool
8. Execute crash analysis commands (bt, log, ps, files, vm)
9. Validate crash analysis output
10. Clean up by unmounting SAN disk and restoring configuration

PowerVM LPAR Support:
- Detects LPAR environment (FSP_PHYP, EBMC_PHYP)
- Uses HMC for crash triggering via dumprestart
- Handles LPAR state transitions properly
- Supports HMC-based operations
"""

import os
import re
import time
import unittest

import pexpect
import OpTestConfiguration
import OpTestLogger
from common.OpTestUtil import OpTestUtil
from common.OpTestSystem import OpSystemState
from common.Exceptions import (CommandFailed, KernelPanic, KernelKdump,
                               KernelCrashUnknown, PlatformError)
from common.OpTestError import OpTestError
from common import OpTestInstallUtil

log = OpTestLogger.optest_logger_glob.get_logger(__name__)


class KernelCrashSANWithAnalysis(unittest.TestCase):
    """
    Enhanced kernel crash dump test with SAN disk target and crash utility analysis.
    
    Supports both PowerNV and PowerVM LPAR environments.
    
    This test case validates the complete workflow of:
    - SAN disk preparation and mounting
    - Kdump configuration for SAN target
    - Kernel crash triggering (echo c or HMC dumprestart for LPAR)
    - Dump collection verification
    - Crash analysis using crash utility
    - Cleanup and restoration
    
    PowerVM LPAR Features:
    - Automatic LPAR detection via BMC type
    - HMC integration for crash triggering
    - LPAR state management
    - Proper handling of LPAR boot sequences
    """

    def setUp(self):
        """
        Pre-setup before starting the SAN dump test with analysis.
        Initializes framework objects and validates prerequisites.
        """
        conf = OpTestConfiguration.conf
        self.cv_SYSTEM = conf.system()
        self.cv_HOST = conf.host()
        self.cv_BMC = conf.bmc()
        self.bmc_type = conf.args.bmc_type
        self.util = self.cv_SYSTEM.util
        self.op_test_util = OpTestUtil(conf)
        self.c = self.cv_SYSTEM.console
        
        # Get distribution information
        self.distro = self.op_test_util.distro_name()
        self.version = self.op_test_util.get_distro_version().split(".")[0]
        
        # Check if running on LPAR
        if self.bmc_type == "FSP_PHYP" or self.bmc_type == "EBMC_PHYP":
            self.is_lpar = True
            self.hmc_user = conf.args.hmc_username
            self.hmc_password = conf.args.hmc_password
            self.hmc_ip = conf.args.hmc_ip
            self.lpar_name = conf.args.lpar_name
            self.system_name = conf.args.system_name
            self.cv_HMC = self.cv_SYSTEM.hmc
            log.info("PowerVM LPAR environment detected")
            log.info("HMC: %s, System: %s, LPAR: %s" % (self.hmc_ip, self.system_name, self.lpar_name))
        else:
            self.is_lpar = False
            log.info("PowerNV (bare-metal) environment detected")
        
        # SAN disk configuration
        try:
            self.san_disk = conf.args.san_disk
        except AttributeError:
            raise self.skipTest("--san-disk parameter required (e.g., /dev/sdb)")
        
        # Mount point for SAN disk
        self.san_mount_point = "/mnt/kdump_san"
        self.original_kdump_config = None
        self.crash_content = []
        
        # Ensure system is in OS state
        self.cv_SYSTEM.goto_state(OpSystemState.OS)
        
        # Detect distribution
        res = self.cv_HOST.host_run_command("cat /etc/os-release", timeout=60)
        if "Ubuntu" in res[0] or "Ubuntu" in res[1]:
            self.distro = "ubuntu"
        elif 'Red Hat' in res[0] or 'Red Hat' in res[1]:
            self.distro = 'rhel'
        elif 'SLES' in res[0] or 'SLES' in res[1]:
            self.distro = 'sles'
        else:
            raise self.skipTest("Test currently supported only on Ubuntu, SLES and RHEL")
        
        log.info("SAN Disk Kernel Dump Analysis Test - setUp complete")

    def format_san_disk(self):
        """
        Format the SAN disk LUN with EXT4 filesystem.
        
        Raises:
            CommandFailed: If formatting fails
            OpTestError: If disk is not available
        """
        log.info("Formatting SAN disk %s with EXT4 filesystem" % self.san_disk)
        
        # Verify disk exists
        try:
            self.c.run_command("ls -l %s" % self.san_disk)
        except CommandFailed:
            raise OpTestError("SAN disk %s not found" % self.san_disk)
        
        # Unmount if already mounted
        try:
            self.c.run_command("umount %s 2>/dev/null || true" % self.san_disk)
        except CommandFailed:
            pass  # Ignore if not mounted
        
        # Format with EXT4
        try:
            self.c.run_command("mkfs.ext4 -F %s" % self.san_disk, timeout=300)
            log.info("Successfully formatted %s with EXT4" % self.san_disk)
        except CommandFailed as e:
            raise OpTestError("Failed to format SAN disk: %s" % str(e))

    def mount_san_disk(self):
        """
        Mount the formatted SAN disk to designated mount point and add to fstab.
        
        Raises:
            CommandFailed: If mount operation fails
            OpTestError: If mount point creation fails
        """
        log.info("Mounting SAN disk to %s" % self.san_mount_point)
        
        # Create mount point directory
        try:
            self.c.run_command("mkdir -p %s" % self.san_mount_point)
        except CommandFailed as e:
            raise OpTestError("Failed to create mount point: %s" % str(e))
        
        # Mount the disk
        try:
            self.c.run_command("mount %s %s" % (self.san_disk, self.san_mount_point))
            log.info("Successfully mounted %s to %s" % (self.san_disk, self.san_mount_point))
        except CommandFailed as e:
            raise OpTestError("Failed to mount SAN disk: %s" % str(e))
        
        # Verify mount
        mount_check = self.c.run_command("mount | grep %s" % self.san_mount_point)
        if not mount_check:
            raise OpTestError("Mount verification failed for %s" % self.san_mount_point)
        
        # Add to fstab for persistence
        try:
            # Get UUID of the disk
            uuid_output = self.c.run_command("blkid %s | grep -o 'UUID=\"[^\"]*\"' | cut -d'\"' -f2" % self.san_disk)
            if uuid_output:
                uuid = uuid_output[0].strip()
                fstab_entry = "UUID=%s %s ext4 defaults 0 2" % (uuid, self.san_mount_point)
                
                # Backup original fstab
                self.c.run_command("cp /etc/fstab /etc/fstab.bak_kdump")
                
                # Add entry if not already present
                self.c.run_command("grep -q '%s' /etc/fstab || echo '%s' >> /etc/fstab" % 
                                 (self.san_mount_point, fstab_entry))
                log.info("Added SAN disk to /etc/fstab")
        except CommandFailed as e:
            log.warning("Failed to add to fstab: %s" % str(e))

    def configure_kdump_san(self):
        """
        Configure kdump to use SAN mount point as dump target.
        
        Raises:
            CommandFailed: If kdump configuration fails
        """
        log.info("Configuring kdump to use SAN mount point %s" % self.san_mount_point)
        
        # Backup original kdump configuration
        if self.distro == 'rhel':
            self.c.run_command("cp /etc/kdump.conf /etc/kdump.conf.bak_san")
            # Configure kdump path
            self.c.run_command("sed -i 's|^path.*|path %s|' /etc/kdump.conf" % self.san_mount_point)
            # Ensure path directive exists
            self.c.run_command("grep -q '^path' /etc/kdump.conf || echo 'path %s' >> /etc/kdump.conf" % 
                             self.san_mount_point)
        elif self.distro == 'sles':
            self.c.run_command("cp /etc/sysconfig/kdump /etc/sysconfig/kdump.bak_san")
            self.c.run_command("sed -i 's|^KDUMP_SAVEDIR=.*|KDUMP_SAVEDIR=\"file://%s\"|' /etc/sysconfig/kdump" % 
                             self.san_mount_point)
        elif self.distro == 'ubuntu':
            # Ubuntu uses /etc/default/kdump-tools
            self.c.run_command("cp /etc/default/kdump-tools /etc/default/kdump-tools.bak_san 2>/dev/null || true")
            self.c.run_command("sed -i 's|^KDUMP_COREDIR=.*|KDUMP_COREDIR=\"%s\"|' /etc/default/kdump-tools" % 
                             self.san_mount_point)
        
        # Restart kdump service
        try:
            self.c.run_command("systemctl restart kdump.service", timeout=120)
            time.sleep(5)
            
            # Verify kdump service is active
            status = self.c.run_command("systemctl is-active kdump.service")
            if "active" not in status[0]:
                raise OpTestError("kdump service failed to start")
            
            log.info("kdump service restarted successfully with SAN configuration")
        except CommandFailed as e:
            raise OpTestError("Failed to restart kdump service: %s" % str(e))

    def setup_crash_content_baseline(self):
        """
        Record current crash directories before triggering crash.
        This helps identify new crash dumps after kernel crash.
        """
        log.info("Recording baseline crash content in %s" % self.san_mount_point)
        try:
            self.crash_content = self.c.run_command(
                "ls -l %s 2>/dev/null | grep '^d' | awk '{print $9}' || true" % self.san_mount_point)
            log.debug("Baseline crash content: %s" % self.crash_content)
        except CommandFailed:
            self.crash_content = []

    def trigger_kernel_crash(self, crash_type="echo_c"):
        """
        Trigger kernel crash and wait for system to dump and reboot.
        
        Args:
            crash_type: Type of crash trigger - "echo_c" for sysrq, "hmc" for HMC dumprestart
        
        Returns:
            str: Boot type after crash (KDUMPKERNEL, NORMAL, etc.)
            
        Raises:
            OpTestError: If crash trigger or recovery fails
        """
        log.info("Triggering kernel crash to generate vmcore dump (type: %s)" % crash_type)
        
        # Disable fast-reboot for proper crash handling (PowerNV only)
        if not self.is_lpar:
            try:
                self.c.run_command("nvram -p ibm,skiboot --update-config fast-reset=0")
                log.info("Disabled fast-reboot for proper crash handling")
            except CommandFailed:
                log.warning("Failed to disable fast-reboot, continuing anyway")
        
        # Set panic timeout
        self.c.run_command("echo 10 > /proc/sys/kernel/panic")
        
        # Enable sysrq
        self.c.pty.sendline("echo 1 > /proc/sys/kernel/sysrq")
        
        # Trigger crash based on type
        if crash_type == "hmc" and self.is_lpar:
            log.info("Triggering crash via HMC dumprestart command")
            try:
                self.cv_HMC.run_command("chsysstate -r lpar -m %s -n %s -o dumprestart" %
                                       (self.system_name, self.lpar_name), timeout=300)
                log.info("HMC dumprestart command sent successfully")
            except Exception as e:
                log.error("Failed to trigger HMC dumprestart: %s" % str(e))
                raise OpTestError("HMC dumprestart failed: %s" % str(e))
        else:
            log.info("Triggering crash via sysrq (echo c)")
            self.c.pty.sendline("echo c > /proc/sysrq-trigger")
        
        # Wait for crash, dump, and reboot
        boot_type = "UNKNOWN"
        done = False
        rc = -1
        
        while not done:
            try:
                # Wait for kdump completion and reboot
                rc = self.c.pty.expect(
                    ["saving vmcore complete", "saved vmcore", "Rebooting."], 
                    timeout=1800)
            except KernelKdump:
                log.info("Kdump kernel boot detected")
                boot_type = "KDUMPKERNEL"
            except KernelPanic:
                log.info("Kernel panic detected")
                boot_type = "NORMAL"
            except KernelCrashUnknown:
                self.cv_SYSTEM.set_state(OpSystemState.UNKNOWN_BAD)
                done = True
                boot_type = "UNKNOWN"
            except PlatformError:
                log.info("Platform error detected during crash")
                done = True
                boot_type = "NORMAL"
            except pexpect.TIMEOUT:
                log.warning("Timeout waiting for crash completion")
                done = True
                boot_type = "UNKNOWN"
                self.cv_SYSTEM.set_state(OpSystemState.UNKNOWN_BAD)
            except Exception as e:
                log.error("Exception during crash handling: %s" % str(e))
                done = True
                boot_type = "UNKNOWN"
            
            if rc >= 0:
                log.info("Kdump finished collecting core file, waiting for system to boot")
                if self.is_lpar:
                    log.info("LPAR environment: Setting state to UNKNOWN for proper boot detection")
                    self.cv_SYSTEM.set_state(OpSystemState.UNKNOWN)
                done = True
            
            # For LPAR: Check if LPAR is in "Not Activated" state
            if self.is_lpar and hasattr(self, 'cv_HMC'):
                try:
                    lpar_state = self.cv_HMC.get_lpar_state()
                    log.info("LPAR state: %s" % lpar_state)
                    if lpar_state == "Not Activated":
                        log.info("LPAR is Not Activated, crash dump should be complete")
                        return boot_type
                except Exception as e:
                    log.warning("Failed to get LPAR state: %s" % str(e))
        
        # Wait for system to return to OS
        log.info("Waiting for system to boot back to OS...")
        self.cv_SYSTEM.goto_state(OpSystemState.OS)
        log.info("System booted successfully to OS")
        
        return boot_type

    def verify_dump_on_san(self):
        """
        Verify that vmcore dump file was successfully written to SAN disk.
        
        Returns:
            str: Path to the crash directory containing vmcore
            
        Raises:
            OpTestError: If dump file not found or incomplete
        """
        log.info("Verifying dump file on SAN disk %s" % self.san_mount_point)
        
        # Get current crash directories
        crash_content_after = self.c.run_command(
            "ls -l %s 2>/dev/null | grep '^d' | awk '{print $9}' || true" % self.san_mount_point)
        
        # Find new crash directory
        new_crash_dirs = list(set(crash_content_after) - set(self.crash_content))
        
        # Filter for valid crash directory names
        if self.distro == "sles":
            new_crash_dirs = list(filter(lambda x: re.search(r'\d{4}-\d{2}-\d{2}-\d{2}-\d{2}', x), 
                                        new_crash_dirs))
        else:
            new_crash_dirs = list(filter(lambda x: re.search(r'\d{4}-\d{2}-\d{2}-\d{2}:\d{2}', x), 
                                        new_crash_dirs))
        
        if not new_crash_dirs:
            raise OpTestError("Dump directory not created on SAN disk")
        
        crash_dir = new_crash_dirs[0]
        crash_path = "%s/%s" % (self.san_mount_point, crash_dir)
        log.info("Found crash directory: %s" % crash_path)
        
        # Verify vmcore file exists
        try:
            vmcore_files = self.c.run_command("ls %s/vmcore* 2>/dev/null" % crash_path)
            
            # Check for incomplete dump indicator
            if any("vmcore-dmesg-incomplete.txt" in f for f in vmcore_files):
                raise OpTestError("kdump failed - vmcore-dmesg-incomplete.txt found")
            
            # Verify actual vmcore file exists
            actual_vmcore = [f for f in vmcore_files if f.startswith("%s/vmcore" % crash_path) 
                           and not f.endswith("vmcore-dmesg.txt")]
            
            if not actual_vmcore:
                raise OpTestError("vmcore file not found in %s" % crash_path)
            
            log.info("Successfully verified vmcore file: %s" % actual_vmcore[0])
            return crash_path
            
        except CommandFailed as e:
            raise OpTestError("Failed to verify vmcore file: %s" % str(e))

    def install_crash_utility(self):
        """
        Install crash utility tool if not already installed.
        
        Raises:
            CommandFailed: If installation fails
        """
        log.info("Checking and installing crash utility if needed")
        
        # Check if crash is already installed
        try:
            self.c.run_command("which crash")
            log.info("crash utility already installed")
            return
        except CommandFailed:
            pass
        
        # Install based on distribution
        try:
            if self.distro == "rhel":
                self.c.run_command("yum install -y crash", timeout=300)
            elif self.distro == "sles":
                self.c.run_command("zypper install -y crash", timeout=300)
            elif self.distro == "ubuntu":
                self.c.run_command("apt-get update && apt-get install -y crash", timeout=300)
            
            log.info("crash utility installed successfully")
        except CommandFailed as e:
            raise OpTestError("Failed to install crash utility: %s" % str(e))

    def perform_crash_analysis(self, crash_path):
        """
        Perform comprehensive crash analysis using crash utility.
        
        Args:
            crash_path: Path to crash directory containing vmcore
            
        Returns:
            dict: Dictionary containing analysis results
            
        Raises:
            OpTestError: If crash analysis fails
        """
        log.info("Performing crash analysis on vmcore in %s" % crash_path)
        
        # Find vmcore file
        vmcore_files = self.c.run_command("ls %s/vmcore* 2>/dev/null | grep -v dmesg" % crash_path)
        if not vmcore_files:
            raise OpTestError("No vmcore file found for analysis")
        
        vmcore_path = vmcore_files[0].strip()
        log.info("Analyzing vmcore: %s" % vmcore_path)
        
        # Get kernel version for debug symbols
        try:
            kernel_version = self.c.run_command("uname -r")[0].strip()
            log.info("Current kernel version: %s" % kernel_version)
        except CommandFailed:
            kernel_version = None
        
        analysis_results = {}
        
        # Create crash analysis script
        crash_script = "/tmp/crash_analysis.cmd"
        crash_commands = [
            "bt",           # Backtrace
            "log",          # Kernel log buffer
            "ps",           # Process status at crash time
            "files",        # Open file descriptors
            "vm",           # Virtual memory information
            "sys",          # System information
            "mod",          # Loaded modules
        ]
        
        # Write crash commands to script file
        script_content = "\n".join(crash_commands) + "\nquit\n"
        self.c.run_command("echo '%s' > %s" % (script_content, crash_script))
        
        # Run crash analysis
        try:
            log.info("Running crash utility analysis...")
            crash_cmd = "crash -s %s /usr/lib/debug/boot/vmlinux-%s %s 2>&1" % (
                crash_script, kernel_version, vmcore_path)
            
            # Run with extended timeout as analysis can take time
            crash_output = self.c.run_command(crash_cmd, timeout=600)
            
            # Parse and store results
            analysis_results['full_output'] = "\n".join(crash_output)
            
            # Extract specific sections
            output_text = "\n".join(crash_output)
            
            # Extract backtrace
            if "BACKTRACE:" in output_text or "#0 " in output_text:
                bt_start = output_text.find("bt")
                bt_end = output_text.find("crash>", bt_start + 1)
                if bt_start >= 0 and bt_end > bt_start:
                    analysis_results['backtrace'] = output_text[bt_start:bt_end].strip()
                    log.info("Backtrace extracted successfully")
            
            # Extract kernel log
            if "KERNEL:" in output_text or "Linux version" in output_text:
                log_start = output_text.find("log")
                log_end = output_text.find("crash>", log_start + 1)
                if log_start >= 0 and log_end > log_start:
                    analysis_results['kernel_log'] = output_text[log_start:log_end].strip()
                    log.info("Kernel log extracted successfully")
            
            # Extract process list
            if "PID" in output_text and "COMMAND" in output_text:
                ps_start = output_text.find("ps")
                ps_end = output_text.find("crash>", ps_start + 1)
                if ps_start >= 0 and ps_end > ps_start:
                    analysis_results['process_list'] = output_text[ps_start:ps_end].strip()
                    log.info("Process list extracted successfully")
            
            log.info("Crash analysis completed successfully")
            
        except CommandFailed as e:
            log.warning("Crash analysis encountered issues: %s" % str(e))
            # Don't fail the test, just log the issue
            analysis_results['error'] = str(e)
        
        return analysis_results

    def validate_crash_analysis(self, analysis_results):
        """
        Validate that crash analysis output is complete and readable.
        
        Args:
            analysis_results: Dictionary containing analysis results
            
        Raises:
            OpTestError: If analysis is incomplete or invalid
        """
        log.info("Validating crash analysis results")
        
        if 'error' in analysis_results:
            log.warning("Crash analysis had errors: %s" % analysis_results['error'])
        
        if 'full_output' not in analysis_results or not analysis_results['full_output']:
            raise OpTestError("Crash analysis produced no output")
        
        # Check for critical sections
        validations = []
        
        if 'backtrace' in analysis_results:
            validations.append("Backtrace: PRESENT")
            log.info("✓ Backtrace information available")
        else:
            validations.append("Backtrace: MISSING")
            log.warning("✗ Backtrace information not found")
        
        if 'kernel_log' in analysis_results:
            validations.append("Kernel Log: PRESENT")
            log.info("✓ Kernel log information available")
        else:
            validations.append("Kernel Log: MISSING")
            log.warning("✗ Kernel log information not found")
        
        if 'process_list' in analysis_results:
            validations.append("Process List: PRESENT")
            log.info("✓ Process list information available")
        else:
            validations.append("Process List: MISSING")
            log.warning("✗ Process list information not found")
        
        # Log validation summary
        log.info("Crash Analysis Validation Summary:")
        for validation in validations:
            log.info("  %s" % validation)
        
        # Ensure at least some data was extracted
        if not any(['backtrace' in analysis_results, 'kernel_log' in analysis_results, 
                   'process_list' in analysis_results]):
            raise OpTestError("Crash analysis failed to extract any meaningful data")
        
        log.info("Crash analysis validation completed")

    def cleanup_san_configuration(self):
        """
        Clean up by unmounting SAN disk and restoring original kdump configuration.
        """
        log.info("Cleaning up SAN configuration")
        
        # Restore original kdump configuration
        try:
            if self.distro == 'rhel':
                self.c.run_command("cp /etc/kdump.conf.bak_san /etc/kdump.conf 2>/dev/null || true")
            elif self.distro == 'sles':
                self.c.run_command("cp /etc/sysconfig/kdump.bak_san /etc/sysconfig/kdump 2>/dev/null || true")
            elif self.distro == 'ubuntu':
                self.c.run_command("cp /etc/default/kdump-tools.bak_san /etc/default/kdump-tools 2>/dev/null || true")
            
            # Restart kdump service with original config
            self.c.run_command("systemctl restart kdump.service 2>/dev/null || true", timeout=120)
            log.info("Restored original kdump configuration")
        except CommandFailed as e:
            log.warning("Failed to restore kdump configuration: %s" % str(e))
        
        # Restore fstab
        try:
            self.c.run_command("cp /etc/fstab.bak_kdump /etc/fstab 2>/dev/null || true")
            log.info("Restored original fstab")
        except CommandFailed as e:
            log.warning("Failed to restore fstab: %s" % str(e))
        
        # Unmount SAN disk
        try:
            self.c.run_command("umount %s 2>/dev/null || true" % self.san_mount_point)
            log.info("Unmounted SAN disk from %s" % self.san_mount_point)
        except CommandFailed as e:
            log.warning("Failed to unmount SAN disk: %s" % str(e))
        
        # Remove mount point
        try:
            self.c.run_command("rmdir %s 2>/dev/null || true" % self.san_mount_point)
        except CommandFailed:
            pass
        
        log.info("Cleanup completed")

    def runTest(self):
        """
        Main test execution method following op-test framework patterns.
        
        Test workflow:
        1. Format SAN disk with EXT4
        2. Mount SAN disk and add to fstab
        3. Configure kdump for SAN target
        4. Record baseline crash content
        5. Trigger kernel crash
        6. Verify dump on SAN disk
        7. Install crash utility
        8. Perform crash analysis
        9. Validate analysis results
        10. Cleanup configuration
        """
        log.info("=" * 80)
        log.info("Starting Enhanced Kernel Crash Dump Test with SAN and Analysis")
        log.info("=" * 80)
        
        try:
            # Step 1: Format SAN disk
            log.info("Step 1: Formatting SAN disk")
            self.format_san_disk()
            
            # Step 2: Mount SAN disk
            log.info("Step 2: Mounting SAN disk")
            self.mount_san_disk()
            
            # Step 3: Configure kdump
            log.info("Step 3: Configuring kdump for SAN target")
            self.configure_kdump_san()
            
            # Step 4: Setup baseline
            log.info("Step 4: Recording baseline crash content")
            self.setup_crash_content_baseline()
            
            # Step 5: Trigger crash (use HMC method for LPAR)
            log.info("Step 5: Triggering kernel crash")
            if self.is_lpar:
                log.info("Using HMC dumprestart for LPAR crash trigger")
                boot_type = self.trigger_kernel_crash(crash_type="hmc")
            else:
                log.info("Using sysrq for PowerNV crash trigger")
                boot_type = self.trigger_kernel_crash(crash_type="echo_c")
            log.info("Boot type after crash: %s" % boot_type)
            
            # Step 6: Verify dump
            log.info("Step 6: Verifying dump on SAN disk")
            crash_path = self.verify_dump_on_san()
            
            # Step 7: Install crash utility
            log.info("Step 7: Installing crash utility")
            self.install_crash_utility()
            
            # Step 8: Perform analysis
            log.info("Step 8: Performing crash analysis")
            analysis_results = self.perform_crash_analysis(crash_path)
            
            # Step 9: Validate analysis
            log.info("Step 9: Validating crash analysis results")
            self.validate_crash_analysis(analysis_results)
            
            log.info("=" * 80)
            log.info("Test PASSED: Kernel crash dump to SAN with analysis completed successfully")
            log.info("=" * 80)
            
        except Exception as e:
            log.error("Test FAILED: %s" % str(e))
            raise
        finally:
            # Step 10: Cleanup (always execute)
            log.info("Step 10: Cleaning up configuration")
            self.cleanup_san_configuration()

    def tearDown(self):
        """
        Post-test cleanup to ensure system is in good state.
        """
        log.info("Executing tearDown")
        try:
            # Ensure we're back in OS state
            self.cv_SYSTEM.goto_state(OpSystemState.OS)
        except Exception as e:
            log.warning("tearDown: Failed to return to OS state: %s" % str(e))


def suite():
    """
    Create test suite for SAN-based kernel dump with analysis.
    """
    s = unittest.TestSuite()
    s.addTest(KernelCrashSANWithAnalysis())
    return s

# Made with Bob
