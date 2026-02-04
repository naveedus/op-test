# OpTestKernelDumpSANAnalysis - Enhanced Kernel Crash Dump Test

## Overview

`OpTestKernelDumpSANAnalysis.py` is an enhanced test case for the OpenPower Test Framework that validates kernel crash dump functionality with SAN disk storage and comprehensive crash analysis capabilities.

**Contributors:**
- Naveed AUS <naveedaus@in.ibm.com> - Assisted with AI tools

## Features

### Dual Environment Support
- **PowerNV (Bare-Metal)**: Direct hardware testing with OpenBMC/SMC
- **PowerVM LPAR**: Virtual partition testing with HMC integration

### Complete Workflow
1. **SAN Disk Preparation**
   - Format SAN disk LUN with EXT4 filesystem
   - Mount to designated mount point
   - Add persistent entry to /etc/fstab

2. **Kdump Configuration**
   - Configure kdump service for SAN target
   - Support for RHEL, SLES, and Ubuntu distributions
   - Automatic service restart and validation

3. **Kernel Crash Triggering**
   - PowerNV: sysrq trigger (`echo c > /proc/sysrq-trigger`)
   - PowerVM LPAR: HMC dumprestart command
   - Proper state machine handling

4. **Dump Verification**
   - Validate vmcore file creation on SAN disk
   - Check for incomplete dump indicators
   - Verify dump directory structure

5. **Crash Analysis**
   - Install crash utility tool
   - Execute comprehensive analysis commands:
     - `bt` - Backtrace of crashed kernel
     - `log` - Kernel log buffer
     - `ps` - Process status at crash time
     - `files` - Open file descriptors
     - `vm` - Virtual memory information
     - `sys` - System information
     - `mod` - Loaded kernel modules

6. **Validation & Cleanup**
   - Validate crash analysis completeness
   - Restore original kdump configuration
   - Unmount SAN disk
   - Restore /etc/fstab

## Prerequisites

### Common Requirements
- Python 3.6 or higher
- op-test framework installed
- SAN disk LUN accessible to the test system
- Root/sudo access on target system

### PowerNV (Bare-Metal) Requirements
- OpenBMC or SMC BMC
- BMC credentials (SSH and IPMI)
- Host OS credentials

### PowerVM LPAR Requirements
- HMC (Hardware Management Console) access
- HMC credentials
- System name and LPAR name
- LPAR OS credentials

## Installation

1. Ensure op-test framework is installed:
```bash
cd op-test
pip3 install -r requirements.txt
```

2. Copy the test file to testcases directory (if not already there):
```bash
cp OpTestKernelDumpSANAnalysis.py op-test/testcases/
```

3. Verify the test is recognized:
```bash
./op-test --list-suites | grep -i san
```

## Usage

### PowerNV (Bare-Metal) Example

```bash
./op-test \
  --bmc-type OpenBMC \
  --bmc-ip 192.168.1.100 \
  --bmc-username root \
  --bmc-password 0penBmc \
  --host-ip 192.168.1.101 \
  --host-user root \
  --host-password password123 \
  --san-disk /dev/sdb \
  --run testcases.OpTestKernelDumpSANAnalysis.KernelCrashSANWithAnalysis
```

### PowerVM LPAR Example

```bash
./op-test \
  --bmc-type FSP_PHYP \
  --hmc-ip 192.168.1.50 \
  --hmc-username hscroot \
  --hmc-password abc123 \
  --system-name Server-8203-E4A-SN1234567 \
  --lpar-name lpar1 \
  --host-ip 192.168.1.102 \
  --host-user root \
  --host-password password123 \
  --san-disk /dev/sdc \
  --run testcases.OpTestKernelDumpSANAnalysis.KernelCrashSANWithAnalysis
```

### Using Configuration File

Create `~/.op-test-framework.conf`:

```ini
[op-test]
# For PowerNV
bmc_type=OpenBMC
bmc_ip=192.168.1.100
bmc_username=root
bmc_password=0penBmc
host_ip=192.168.1.101
host_user=root
host_password=password123
san_disk=/dev/sdb

# For PowerVM LPAR (comment out PowerNV settings above)
# bmc_type=FSP_PHYP
# hmc_ip=192.168.1.50
# hmc_username=hscroot
# hmc_password=abc123
# system_name=Server-8203-E4A-SN1234567
# lpar_name=lpar1
# host_ip=192.168.1.102
# host_user=root
# host_password=password123
# san_disk=/dev/sdc
```

Then run:
```bash
./op-test --run testcases.OpTestKernelDumpSANAnalysis.KernelCrashSANWithAnalysis
```

## Command Line Parameters

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--san-disk` | SAN disk device path | `/dev/sdb` |
| `--host-ip` | Target system IP address | `192.168.1.101` |
| `--host-user` | Host OS username | `root` |
| `--host-password` | Host OS password | `password123` |

### PowerNV Specific

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--bmc-type` | BMC type | `OpenBMC`, `SMC` |
| `--bmc-ip` | BMC IP address | `192.168.1.100` |
| `--bmc-username` | BMC SSH username | `root` |
| `--bmc-password` | BMC SSH password | `0penBmc` |
| `--bmc-usernameipmi` | BMC IPMI username | `ADMIN` |
| `--bmc-passwordipmi` | BMC IPMI password | `admin` |

### PowerVM LPAR Specific

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--bmc-type` | BMC type for LPAR | `FSP_PHYP`, `EBMC_PHYP` |
| `--hmc-ip` | HMC IP address | `192.168.1.50` |
| `--hmc-username` | HMC username | `hscroot` |
| `--hmc-password` | HMC password | `abc123` |
| `--system-name` | Managed system name | `Server-8203-E4A-SN1234567` |
| `--lpar-name` | LPAR name | `lpar1` |

## Test Workflow Details

### Step 1: Format SAN Disk
- Verifies SAN disk exists
- Unmounts if already mounted
- Formats with EXT4 filesystem
- Timeout: 300 seconds

### Step 2: Mount SAN Disk
- Creates mount point directory (`/mnt/kdump_san`)
- Mounts SAN disk
- Verifies mount success
- Adds UUID-based entry to /etc/fstab
- Backs up original fstab

### Step 3: Configure Kdump
- Backs up original kdump configuration
- Updates kdump path/directory to SAN mount point
- Distribution-specific configuration:
  - **RHEL**: `/etc/kdump.conf`
  - **SLES**: `/etc/sysconfig/kdump`
  - **Ubuntu**: `/etc/default/kdump-tools`
- Restarts kdump service
- Verifies service is active

### Step 4: Record Baseline
- Lists existing crash directories
- Used to identify new dumps after crash

### Step 5: Trigger Crash
- **PowerNV**: 
  - Disables fast-reboot
  - Sets panic timeout
  - Triggers via sysrq
- **PowerVM LPAR**:
  - Uses HMC dumprestart command
  - Monitors LPAR state
- Waits for dump completion (up to 1800 seconds)
- Handles various exception types:
  - `KernelKdump`: Kdump kernel boot
  - `KernelPanic`: Kernel panic
  - `PlatformError`: Hardware error
  - `TIMEOUT`: Dump timeout

### Step 6: Verify Dump
- Identifies new crash directory
- Validates vmcore file exists
- Checks for incomplete dump indicators
- Verifies file is readable

### Step 7: Install Crash Utility
- Checks if crash utility is installed
- Installs if needed:
  - **RHEL**: `yum install -y crash`
  - **SLES**: `zypper install -y crash`
  - **Ubuntu**: `apt-get install -y crash`

### Step 8: Perform Analysis
- Creates crash command script
- Executes crash utility with vmcore
- Runs analysis commands:
  - `bt`: Stack backtrace
  - `log`: Kernel messages
  - `ps`: Process list
  - `files`: File descriptors
  - `vm`: Memory info
  - `sys`: System info
  - `mod`: Module list
- Timeout: 600 seconds

### Step 9: Validate Analysis
- Checks for backtrace presence
- Verifies kernel log extraction
- Validates process list
- Ensures meaningful data extracted

### Step 10: Cleanup
- Restores original kdump configuration
- Restarts kdump service
- Restores original /etc/fstab
- Unmounts SAN disk
- Removes mount point directory

## Expected Output

### Successful Test Run
```
================================================================================
Starting Enhanced Kernel Crash Dump Test with SAN and Analysis
================================================================================
Step 1: Formatting SAN disk
Successfully formatted /dev/sdb with EXT4
Step 2: Mounting SAN disk
Successfully mounted /dev/sdb to /mnt/kdump_san
Added SAN disk to /etc/fstab
Step 3: Configuring kdump for SAN target
kdump service restarted successfully with SAN configuration
Step 4: Recording baseline crash content
Baseline crash content: []
Step 5: Triggering kernel crash
Triggering kernel crash to generate vmcore dump (type: echo_c)
Kdump kernel boot detected
Kdump finished collecting core file, waiting for system to boot
System booted successfully to OS
Boot type after crash: KDUMPKERNEL
Step 6: Verifying dump on SAN disk
Found crash directory: /mnt/kdump_san/2024-02-04-06:15
Successfully verified vmcore file: /mnt/kdump_san/2024-02-04-06:15/vmcore
Step 7: Installing crash utility
crash utility already installed
Step 8: Performing crash analysis
Analyzing vmcore: /mnt/kdump_san/2024-02-04-06:15/vmcore
Running crash utility analysis...
Backtrace extracted successfully
Kernel log extracted successfully
Process list extracted successfully
Crash analysis completed successfully
Step 9: Validating crash analysis results
Crash Analysis Validation Summary:
  Backtrace: PRESENT
  Kernel Log: PRESENT
  Process List: PRESENT
Crash analysis validation completed
================================================================================
Test PASSED: Kernel crash dump to SAN with analysis completed successfully
================================================================================
Step 10: Cleaning up configuration
Restored original kdump configuration
Restored original fstab
Unmounted SAN disk from /mnt/kdump_san
Cleanup completed
```

## Troubleshooting

### Common Issues

#### 1. SAN Disk Not Found
**Error**: `SAN disk /dev/sdb not found`

**Solution**: 
- Verify SAN disk is properly connected
- Check disk path: `ls -l /dev/sd*`
- Ensure proper multipath configuration if using multipath

#### 2. Kdump Service Failed to Start
**Error**: `kdump service failed to start`

**Solution**:
- Check crashkernel parameter: `cat /proc/cmdline | grep crashkernel`
- Verify sufficient memory reserved
- Check kdump service logs: `journalctl -u kdump.service`
- For RHEL: `kdumpctl status`

#### 3. HMC Connection Failed (LPAR)
**Error**: `HMC dumprestart failed`

**Solution**:
- Verify HMC credentials
- Check HMC connectivity: `ping <hmc-ip>`
- Verify LPAR name and system name
- Check HMC user permissions

#### 4. Crash Analysis Failed
**Error**: `Crash analysis produced no output`

**Solution**:
- Verify kernel debug symbols installed
- Check vmcore file integrity: `file /path/to/vmcore`
- Ensure crash utility version matches kernel
- Install debug symbols: 
  - RHEL: `debuginfo-install kernel`
  - Ubuntu: `apt-get install linux-image-$(uname -r)-dbgsym`

#### 5. Mount Failed
**Error**: `Failed to mount SAN disk`

**Solution**:
- Check filesystem: `fsck /dev/sdb`
- Verify no other process using disk: `lsof | grep /dev/sdb`
- Check mount point permissions
- Review system logs: `dmesg | tail -50`

### Debug Mode

Enable verbose logging:
```bash
./op-test --run testcases.OpTestKernelDumpSANAnalysis.KernelCrashSANWithAnalysis --verbose
```

Check log files:
- Main log: `./main.log`
- Debug log: `./debug.log`

## Limitations

1. **Single SAN Disk**: Test supports one SAN disk at a time
2. **Crash Analysis**: Requires kernel debug symbols for detailed analysis
3. **Distribution Support**: Tested on RHEL, SLES, and Ubuntu
4. **Timeout**: Maximum 1800 seconds (30 minutes) for dump completion
5. **LPAR State**: Requires HMC access for LPAR state monitoring

## Best Practices

1. **Pre-Test Verification**
   - Ensure SAN disk has sufficient space (at least 2x RAM size)
   - Verify crashkernel parameter is set
   - Test HMC connectivity before running (for LPAR)

2. **During Test**
   - Monitor system console for crash progress
   - Check HMC for LPAR state (for LPAR)
   - Allow sufficient time for dump completion

3. **Post-Test**
   - Review crash analysis output
   - Save vmcore for offline analysis if needed
   - Verify system returned to normal operation

4. **Cleanup**
   - Test performs automatic cleanup
   - Verify kdump service is running after test
   - Check /etc/fstab was restored

## Integration with CI/CD

### Jenkins Example
```groovy
pipeline {
    agent any
    stages {
        stage('Kernel Dump Test') {
            steps {
                sh '''
                    cd op-test
                    ./op-test \
                        --bmc-type ${BMC_TYPE} \
                        --bmc-ip ${BMC_IP} \
                        --host-ip ${HOST_IP} \
                        --san-disk ${SAN_DISK} \
                        --run testcases.OpTestKernelDumpSANAnalysis.KernelCrashSANWithAnalysis
                '''
            }
        }
    }
}
```

## Support

For issues or questions:
1. Check op-test documentation: http://open-power.github.io/op-test/
2. Review test logs in `./main.log` and `./debug.log`
3. Open issue on GitHub: https://github.com/open-power/op-test
4. Contact: Naveed AUS <naveedaus@in.ibm.com>

## License

Licensed under the Apache License, Version 2.0
See LICENSE file in the op-test repository for details.

## References

- [op-test Framework](https://github.com/open-power/op-test)
- [Kdump Documentation](https://www.kernel.org/doc/Documentation/kdump/kdump.txt)
- [FADUMP Documentation](https://www.kernel.org/doc/Documentation/powerpc/firmware-assisted-dump.txt)
- [Crash Utility](https://github.com/crash-utility/crash)
- [PowerVM Documentation](https://www.ibm.com/docs/en/powervm)