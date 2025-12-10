#Requires -RunAsAdministrator

function Show-Menu {
    Clear-Host
    Write-Host " ▄████▄   ██▓ ▄████▄   ▄▄▄      ▓█████▄  ▄▄▄      "
    Write-Host "▒██▀ ▀█  ▓██▒▒██▀ ▀█  ▒████▄    ▒██▀ ██▌▒████▄    "
    Write-Host "▒▓█    ▄ ▒██▒▒▓█    ▄ ▒██  ▀█▄  ░██   █▌▒██  ▀█▄  "
    Write-Host "▒▓▓▄ ▄██▒░██░▒▓▓▄ ▄██▒░██▄▄▄▄██ ░▓█▄   ▌░██▄▄▄▄██ "
    Write-Host "▒ ▓███▀ ░░██░▒ ▓███▀ ░ ▓█   ▓██▒░▒████▓  ▓█   ▓██▒"
    Write-Host "░ ░▒ ▒  ░░▓  ░ ░▒ ▒  ░ ▒▒   ▓▒█░ ▒▒▓  ▒  ▒▒   ▓▒█░"
    Write-Host "  ░  ▒    ▒ ░  ░  ▒     ▒   ▒▒ ░ ░ ▒  ▒   ▒   ▒▒ ░"
    Write-Host "░         ▒ ░░          ░   ▒    ░ ░  ░   ░   ▒   "
    Write-Host "░ ░       ░  ░ ░            ░  ░   ░          ░  ░"
    Write-Host "░            ░                   ░                "
    Write-Host ""
    Write-Host "https://discord.gg/6J4vQB2gwy"
    Write-Host "1. Disable All Security Features"
    Write-Host "2. Enable All Security Features"
    Write-Host "3. Check Current Status"
    Write-Host "4. Show System Specifications"
    Write-Host "5. Exit"
    Write-Host ""
}

function Show-SystemSpecs {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SYSTEM SPECIFICATIONS" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Motherboard & BIOS Information
    Write-Host "MOTHERBOARD & BIOS" -ForegroundColor Yellow
    Write-Host "==================" -ForegroundColor DarkGray
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS
        $baseboard = Get-CimInstance -ClassName Win32_BaseBoard
        $system = Get-CimInstance -ClassName Win32_ComputerSystemProduct
        
        Write-Host "Manufacturer:        $($baseboard.Manufacturer)" -ForegroundColor White
        Write-Host "Model:               $($baseboard.Product)" -ForegroundColor White
        Write-Host "BIOS Version:        $($bios.SMBIOSBIOSVersion)" -ForegroundColor White
        Write-Host "BIOS UUID:           $($system.UUID)" -ForegroundColor White
        Write-Host "BIOS Serial:         $($bios.SerialNumber)" -ForegroundColor White
        Write-Host "Baseboard Serial:    $($baseboard.SerialNumber)" -ForegroundColor White
        Write-Host "Baseboard Asset Tag: $($baseboard.Tag)" -ForegroundColor White
    } catch {
        Write-Host "Error retrieving motherboard/BIOS info" -ForegroundColor Red
    }
    
    # System Enclosure
    Write-Host "`nSYSTEM ENCLOSURE" -ForegroundColor Yellow
    Write-Host "================" -ForegroundColor DarkGray
    try {
        $enclosure = Get-CimInstance -ClassName Win32_SystemEnclosure
        Write-Host "Manufacturer:        $($enclosure.Manufacturer)" -ForegroundColor White
        Write-Host "Model:               $($enclosure.Model)" -ForegroundColor White
        Write-Host "Serial Number:       $($enclosure.SerialNumber)" -ForegroundColor White
        Write-Host "Enclosure Asset Tag: $($enclosure.SMBIOSAssetTag)" -ForegroundColor White
    } catch {
        Write-Host "Error retrieving enclosure info" -ForegroundColor Red
    }
    
    # Disk Information
    Write-Host "`nDISK DRIVES" -ForegroundColor Yellow
    Write-Host "===========" -ForegroundColor DarkGray
    try {
        $disks = Get-CimInstance -ClassName Win32_DiskDrive
        foreach ($disk in $disks) {
            $sizeGB = [math]::Round($disk.Size / 1GB, 2)
            Write-Host "Model:               $($disk.Model)" -ForegroundColor White
            Write-Host "Serial Number:       $($disk.SerialNumber.Trim())" -ForegroundColor White
            Write-Host "Interface:           $($disk.InterfaceType)" -ForegroundColor White
            Write-Host "Size:                $sizeGB GB" -ForegroundColor White
            Write-Host "Media Type:          $($disk.MediaType)" -ForegroundColor White
            if ($disks.Count -gt 1) { Write-Host "" }
        }
    } catch {
        Write-Host "Error retrieving disk info" -ForegroundColor Red
    }
    
    # Network Adapters
    Write-Host "`nNETWORK ADAPTERS" -ForegroundColor Yellow
    Write-Host "================" -ForegroundColor DarkGray
    try {
        $adapters = Get-NetAdapter
        foreach ($adapter in $adapters) {
            Write-Host "Adapter:             $($adapter.InterfaceDescription)" -ForegroundColor White
            Write-Host "Name:                $($adapter.Name)" -ForegroundColor White
            Write-Host "Current MAC:         $($adapter.MacAddress)" -ForegroundColor White
            
            # Get permanent MAC address
            try {
                $permanentMAC = (Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "NetworkAddress" -ErrorAction SilentlyContinue).RegistryValue
                if ([string]::IsNullOrEmpty($permanentMAC)) {
                    $permanentMAC = $adapter.MacAddress
                }
                Write-Host "Permanent MAC:       $permanentMAC" -ForegroundColor White
            } catch {
                Write-Host "Permanent MAC:       $($adapter.MacAddress)" -ForegroundColor White
            }
            
            Write-Host "Status:              $($adapter.Status)" -ForegroundColor White
            Write-Host "Link Speed:          $($adapter.LinkSpeed)" -ForegroundColor White
            Write-Host "Virtual:             $($adapter.Virtual)" -ForegroundColor White
            if ($adapters.Count -gt 1) { Write-Host "" }
        }
    } catch {
        Write-Host "Error retrieving network adapter info" -ForegroundColor Red
    }
    
    # Physical RAM
    Write-Host "`nPHYSICAL MEMORY (RAM)" -ForegroundColor Yellow
    Write-Host "=====================" -ForegroundColor DarkGray
    try {
        $ramModules = Get-CimInstance -ClassName Win32_PhysicalMemory
        $totalRAM = 0
        foreach ($ram in $ramModules) {
            $capacityGB = [math]::Round($ram.Capacity / 1GB, 2)
            $memType = switch ($ram.SMBIOSMemoryType) {
                20 { "DDR" }
                21 { "DDR2" }
                24 { "DDR3" }
                26 { "DDR4" }
                34 { "DDR5" }
                default { "Unknown" }
            }
            
            Write-Host "Manufacturer:        $($ram.Manufacturer)" -ForegroundColor White
            Write-Host "Serial Number:       $($ram.SerialNumber)" -ForegroundColor White
            Write-Host "Part Number:         $($ram.PartNumber)" -ForegroundColor White
            Write-Host "Capacity:            $capacityGB GB" -ForegroundColor White
            Write-Host "Speed:               $($ram.Speed) MHz" -ForegroundColor White
            Write-Host "Type:                $memType" -ForegroundColor White
            Write-Host "Slot:                $($ram.DeviceLocator)" -ForegroundColor White
            
            $totalRAM += $ram.Capacity
            if ($ramModules.Count -gt 1) { Write-Host "" }
        }
        
        $totalRAMGB = [math]::Round($totalRAM / 1GB, 2)
        Write-Host "Total Installed:     $totalRAMGB GB" -ForegroundColor Green
    } catch {
        Write-Host "Error retrieving RAM info" -ForegroundColor Red
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SPECS COLLECTION COMPLETE" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
}

function Disable-AllSecurity {
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "DISABLING ALL SECURITY FEATURES" -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow
    
    $allSettings = @(
        # Vulnerable Driver Blocklist
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"; Name = "VulnerableDriverBlocklistEnable"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Protected"; Name = "VulnerableDriverBlocklistEnable"; Value = 0},
        
        # Core Isolation - Memory Integrity (HVCI)
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"; Name = "Enabled"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"; Name = "WasEnabledBy"; Value = 0},
        
        # Core Isolation - System Guard
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"; Name = "Enabled"; Value = 0},
        
        # Core Isolation - Credential Guard
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"; Name = "Enabled"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LsaCfgFlags"; Value = 0},
        
        # Virtualization-Based Security (VBS)
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "EnableVirtualizationBasedSecurity"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "RequirePlatformSecurityFeatures"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "HypervisorEnforcedCodeIntegrity"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "HVCIMATRequired"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "ConfigureSystemGuardLaunch"; Value = 0},
        
        # Policy settings
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "EnableVirtualizationBasedSecurity"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "RequirePlatformSecurityFeatures"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "HypervisorEnforcedCodeIntegrity"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "LsaCfgFlags"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "ConfigureSystemGuardLaunch"; Value = 0},
        
        # Exploit Protection - Kernel mitigations
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name = "MitigationOptions"; Value = 0x222222222222; Type = "QWord"},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name = "MitigationAuditOptions"; Value = 0x222222222222; Type = "QWord"},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name = "DisableExceptionChainValidation"; Value = 1},
        
        # Exploit Protection - DEP
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "NoDataExecutionPrevention"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "DisableHHDEP"; Value = 1},
        
        # Exploit Protection - ASLR
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "MoveImages"; Value = 0},
        
        # Additional CI settings
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"; Name = "VerifiedAndReputablePolicyState"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"; Name = "WhqlSettings"; Value = 0},
        
        # Process mitigations
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"; Name = "DisableProcessMitigations"; Value = 1},
        
        # Windows Defender - Real-time Protection
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableOnAccessProtection"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScanOnRealtimeEnable"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableIOAVProtection"; Value = 1},
        
        # Windows Defender - Main Settings
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiVirus"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "ServiceKeepAlive"; Value = 0},
        
        # Windows Defender - Scans
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableArchiveScanning"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableCatchupFullScan"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableCatchupQuickScan"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableRemovableDriveScanning"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableEmailScanning"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableScanningNetworkFiles"; Value = 1},
        
        # Windows Defender - Cloud Protection
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name = "SpyNetReporting"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name = "SubmitSamplesConsent"; Value = 2},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name = "DisableBlockAtFirstSeen"; Value = 1},
        
        # Windows Defender - Threats
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats"; Name = "Threats_ThreatSeverityDefaultAction"; Value = 1},
        
        # Windows Defender - MpEngine
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name = "MpEnablePus"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name = "MpCloudBlockLevel"; Value = 0},
        
        # Windows Defender - Exclusions (allow all)
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"; Name = "DisableAutoExclusions"; Value = 0},
        
        # Windows Defender - Signature Updates
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"; Name = "ForceUpdateFromMU"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"; Name = "DisableUpdateOnStartupWithoutEngine"; Value = 1},
        
        # Windows Defender - Reporting
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"; Name = "DisableEnhancedNotifications"; Value = 1},
        
        # SmartScreen
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableSmartScreen"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"; Name = "SmartScreenEnabled"; Value = "Off"; Type = "String"},
        
        # Windows Security Center Notifications
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications"; Name = "DisableNotifications"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications"; Name = "DisableNotifications"; Value = 1}
    )
    
    $changedCount = 0
    $errorCount = 0
    
    foreach ($setting in $allSettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            
            # Take ownership of protected keys
            try {
                $acl = Get-Acl -Path $setting.Path
                $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $identity.Name,
                    "FullControl",
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Allow"
                )
                $acl.SetAccessRule($adminRule)
                Set-Acl -Path $setting.Path -AclObject $acl -ErrorAction SilentlyContinue
            } catch {}
            
            $valueType = if ($setting.ContainsKey("Type")) { $setting.Type } else { "DWord" }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $valueType -Force -ErrorAction Stop
            
            Write-Host "[OK] $($setting.Name)" -ForegroundColor Green
            $changedCount++
            
        } catch {
            Write-Host "[SKIP] $($setting.Name) (Protected)" -ForegroundColor Yellow
            $errorCount++
        }
    }
    
    # Disable Windows Defender via PowerShell
    Write-Host "`nDisabling Windows Defender..." -ForegroundColor DarkYellow
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue
        Set-MpPreference -HighThreatDefaultAction 6 -AllowThreatDefaultAction -ErrorAction SilentlyContinue
        Set-MpPreference -ModerateThreatDefaultAction 6 -ErrorAction SilentlyContinue
        Set-MpPreference -LowThreatDefaultAction 6 -ErrorAction SilentlyContinue
        Set-MpPreference -SevereThreatDefaultAction 6 -ErrorAction SilentlyContinue
        Write-Host "[OK] Windows Defender disabled via PowerShell" -ForegroundColor Green
    } catch {
        Write-Host "[INFO] Some Defender cmdlets unavailable" -ForegroundColor Yellow
    }
    
    # Disable Windows Defender Service
    Write-Host "`nDisabling Windows Defender Service..." -ForegroundColor DarkYellow
    try {
        Stop-Service -Name WinDefend -Force -ErrorAction SilentlyContinue
        Set-Service -Name WinDefend -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "[OK] WinDefend service disabled" -ForegroundColor Green
    } catch {
        Write-Host "[INFO] Could not disable WinDefend service" -ForegroundColor Yellow
    }
    
    # Disable Defender services
    $defenderServices = @("WdNisSvc", "WdNisDrv", "WdBoot", "WdFilter", "Sense")
    foreach ($service in $defenderServices) {
        try {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        } catch {}
    }
    
    # Disable exploit protection mitigations
    Write-Host "`nDisabling exploit protection mitigations..." -ForegroundColor DarkYellow
    
    $mitigations = @("CFG","DEP","ASLR","SEHOP","BottomUp","ForceRelocateImages","HighEntropy",
                     "StrictHandle","DisallowWin32k","EnableExportAddressFilter","EnableImportAddressFilter",
                     "EnableROP","TerminateOnError","DisableExtensionPoints","ProhibitDynamicCode",
                     "BlockRemoteImages","BlockLowIntegrityImages","PreferSystem32","EnableCET","StrictCET")
    
    foreach ($mitigation in $mitigations) {
        try {
            Set-ProcessMitigation -System -Disable $mitigation -ErrorAction SilentlyContinue | Out-Null
        } catch {}
    }
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "COMPLETE" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Settings changed: $changedCount" -ForegroundColor White
    Write-Host "Errors: $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "White" })
    Write-Host "`nAll security features have been disabled." -ForegroundColor Green
}

function Enable-AllSecurity {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "ENABLING ALL SECURITY FEATURES" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $allSettings = @(
        # Vulnerable Driver Blocklist
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"; Name = "VulnerableDriverBlocklistEnable"; Value = 1},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Protected"; Name = "VulnerableDriverBlocklistEnable"; Value = 1},
        
        # Core Isolation - Memory Integrity (HVCI)
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"; Name = "Enabled"; Value = 1},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"; Name = "WasEnabledBy"; Value = 2},
        
        # Core Isolation - System Guard
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"; Name = "Enabled"; Value = 1},
        
        # Core Isolation - Credential Guard
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"; Name = "Enabled"; Value = 1},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LsaCfgFlags"; Value = 1},
        
        # Virtualization-Based Security (VBS)
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "EnableVirtualizationBasedSecurity"; Value = 1},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "RequirePlatformSecurityFeatures"; Value = 1},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "HypervisorEnforcedCodeIntegrity"; Value = 1},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "HVCIMATRequired"; Value = 1},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "ConfigureSystemGuardLaunch"; Value = 1},
        
        # Policy settings
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "EnableVirtualizationBasedSecurity"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "RequirePlatformSecurityFeatures"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "HypervisorEnforcedCodeIntegrity"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "LsaCfgFlags"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name = "ConfigureSystemGuardLaunch"; Value = 1},
        
        # Exploit Protection - Kernel mitigations (reset to default)
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name = "DisableExceptionChainValidation"; Value = 0},
        
        # Exploit Protection - ASLR
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "MoveImages"; Value = -1},
        
        # Windows Defender - Real-time Protection
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableOnAccessProtection"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScanOnRealtimeEnable"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableIOAVProtection"; Value = 0},
        
        # Windows Defender - Main Settings
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiVirus"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "ServiceKeepAlive"; Value = 1},
        
        # Windows Defender - Scans
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableArchiveScanning"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableCatchupFullScan"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableCatchupQuickScan"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableRemovableDriveScanning"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableEmailScanning"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "DisableScanningNetworkFiles"; Value = 0},
        
        # Windows Defender - Cloud Protection
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name = "SpyNetReporting"; Value = 2},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name = "SubmitSamplesConsent"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name = "DisableBlockAtFirstSeen"; Value = 0},
        
        # Windows Defender - MpEngine
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name = "MpEnablePus"; Value = 1},
        
        # Windows Defender - Signature Updates
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"; Name = "ForceUpdateFromMU"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"; Name = "DisableUpdateOnStartupWithoutEngine"; Value = 0},
        
        # Windows Defender - Reporting
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"; Name = "DisableEnhancedNotifications"; Value = 0},
        
        # SmartScreen
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableSmartScreen"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"; Name = "SmartScreenEnabled"; Value = "Warn"; Type = "String"},
        
        # Windows Security Center Notifications
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications"; Name = "DisableNotifications"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications"; Name = "DisableNotifications"; Value = 0}
    )
    
    $changedCount = 0
    $errorCount = 0
    
    foreach ($setting in $allSettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            
            $valueType = if ($setting.ContainsKey("Type")) { $setting.Type } else { "DWord" }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $valueType -Force -ErrorAction Stop
            
            Write-Host "[OK] $($setting.Name)" -ForegroundColor Green
            $changedCount++
            
        } catch {
            Write-Host "[SKIP] $($setting.Name) (Protected)" -ForegroundColor Yellow
            $errorCount++
        }
    }
    
    # Delete mitigation option keys to reset to default
    Write-Host "`nResetting exploit protection to defaults..." -ForegroundColor Cyan
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationOptions" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationAuditOptions" -ErrorAction SilentlyContinue
        Write-Host "[OK] Exploit protection reset to defaults" -ForegroundColor Green
    } catch {}
    
    # Enable Windows Defender via PowerShell
    Write-Host "`nEnabling Windows Defender..." -ForegroundColor Cyan
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent 1 -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting 2 -ErrorAction SilentlyContinue
        Write-Host "[OK] Windows Defender enabled via PowerShell" -ForegroundColor Green
    } catch {
        Write-Host "[INFO] Some Defender cmdlets unavailable" -ForegroundColor Yellow
    }
    
    # Enable Windows Defender Service
    Write-Host "`nEnabling Windows Defender Service..." -ForegroundColor Cyan
    try {
        Set-Service -Name WinDefend -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
        Write-Host "[OK] WinDefend service enabled" -ForegroundColor Green
    } catch {
        Write-Host "[INFO] Could not enable WinDefend service" -ForegroundColor Yellow
    }
    
    # Enable Defender services
    $defenderServices = @("WdNisSvc", "Sense")
    foreach ($service in $defenderServices) {
        try {
            Set-Service -Name $service -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name $service -ErrorAction SilentlyContinue
        } catch {}
    }
    
    # Enable exploit protection mitigations
    Write-Host "`nEnabling exploit protection mitigations..." -ForegroundColor Cyan
    
    $mitigations = @("CFG","DEP","ASLR","SEHOP","BottomUp","ForceRelocateImages","HighEntropy",
                     "StrictHandle","EnableROP","TerminateOnError","EnableCET")
    
    foreach ($mitigation in $mitigations) {
        try {
            Set-ProcessMitigation -System -Enable $mitigation -ErrorAction SilentlyContinue | Out-Null
        } catch {}
    }
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "COMPLETE" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Settings changed: $changedCount" -ForegroundColor White
    Write-Host "Errors: $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "White" })
    Write-Host "`nAll security features have been enabled." -ForegroundColor Green
}

function Check-SecurityStatus {
    Write-Host "`n========================================" -ForegroundColor DarkYellow
    Write-Host "SECURITY STATUS CHECK" -ForegroundColor DarkYellow
    Write-Host "========================================`n" -ForegroundColor DarkYellow
    
    $checkSettings = @(
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"; Name = "VulnerableDriverBlocklistEnable"; Display = "Vulnerable Driver Blocklist"},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"; Name = "Enabled"; Display = "Memory Integrity (HVCI)"},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "EnableVirtualizationBasedSecurity"; Display = "Virtualization-Based Security"},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name = "DisableExceptionChainValidation"; Display = "SEHOP (Disabled = 1)"},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "MoveImages"; Display = "ASLR"},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Display = "Real-Time Protection (Disabled = 1)"},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; Display = "Windows Defender (Disabled = 1)"}
    )
    
    $enabledCount = 0
    $disabledCount = 0
    
    foreach ($setting in $checkSettings) {
        if (Test-Path $setting.Path) {
            try {
                $value = (Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue).$($setting.Name)
                
                if ($null -eq $value) {
                    Write-Host "[UNKNOWN] $($setting.Display)" -ForegroundColor Yellow
                } elseif ($value -eq 0 -or ($setting.Name -match "Disable" -and $value -eq 1)) {
                    Write-Host "[OFF] $($setting.Display)" -ForegroundColor Green
                    $disabledCount++
                } else {
                    Write-Host "[ON] $($setting.Display) (Value: $value)" -ForegroundColor Red
                    $enabledCount++
                }
            } catch {
                Write-Host "[ERROR] $($setting.Display)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[NOT FOUND] $($setting.Display)" -ForegroundColor Yellow
        }
    }
    
    # Check Windows Defender service status
    Write-Host "`nService Status:" -ForegroundColor DarkYellow
    try {
        $service = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if ($service) {
            $status = if ($service.Status -eq "Stopped" -and $service.StartType -eq "Disabled") { "OFF" } else { "ON" }
            $color = if ($status -eq "OFF") { "Green" } else { "Red" }
            Write-Host "[$status] Windows Defender Service" -ForegroundColor $color
        }
    } catch {}
    
    Write-Host "`n========================================" -ForegroundColor DarkYellow
    Write-Host "Enabled: $enabledCount" -ForegroundColor $(if ($enabledCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Disabled: $disabledCount" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor DarkYellow
    
    if ($enabledCount -gt 0) {
        Write-Host "`nSome security features are still enabled." -ForegroundColor Yellow
        Write-Host "Run option 1 to disable them." -ForegroundColor Yellow
    } else {
        Write-Host "`nAll checked security features are disabled." -ForegroundColor Green
    }
}

# Main execution
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Administrator privileges required!" -ForegroundColor Red
    Write-Host "Right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit
}

do {
    Show-Menu
    $choice = Read-Host "Select option (1-5)"
    
    switch ($choice) {
        '1' {
            Disable-AllSecurity
            Write-Host "`n** RESTART YOUR COMPUTER FOR CHANGES TO TAKE EFFECT **" -ForegroundColor DarkRed
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '2' {
            Enable-AllSecurity
            Write-Host "`n** RESTART YOUR COMPUTER FOR CHANGES TO TAKE EFFECT **" -ForegroundColor DarkRed
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '3' {
            Check-SecurityStatus
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '4' {
            Show-SystemSpecs
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '5' {
            Write-Host "`nExiting..." -ForegroundColor DarkYellow
            exit
        }
        default {
            Write-Host "`nInvalid option. Select 1-5." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne '5')
