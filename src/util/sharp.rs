use actix_web::web;
use server::links::Links;
use std::fs;

// internal packages
use crate::server;
use crate::util;

pub fn sharp_link(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() < 3 {
        sharp_link_help();
        return;
    }
    util::nonstd::execute_assembly(links, link_index, command);
}

pub fn get_sharp_path(tool: String) -> String {
    let mut sharp_collection = std::collections::HashMap::new();
    let home_dir = match std::env::var("HOME") {
        Err(e) => {
            println!("{}", e);
            return "".to_string();
        }
        Ok(home) => home,
    };
    let sharpcollection_path = format!("{}/.link/3rdparty/SharpCollection", home_dir);
    let net40_path = format!("{}/NetFramework_4.0_x64", sharpcollection_path);
    let net45_path = format!("{}/NetFramework_4.5_x64", sharpcollection_path);
    let net47_path = format!("{}/NetFramework_4.7_x64", sharpcollection_path);
    sharp_collection.insert("AD", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("ADCollector", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("ADSearch", format!("{}/{}.exe", net47_path, tool));
    sharp_collection.insert("AtYourService", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("BetterSafetyKatz", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("Grouper2", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("InveighZero", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("LockLess", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("PurpleSharp", format!("{}/{}.exe", net45_path, tool));
    sharp_collection.insert("Rubeus", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SafetyKatz", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SauronEye", format!("{}/{}.exe", net47_path, tool));
    sharp_collection.insert("scout", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SearchOutlook", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("Seatbelt", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpAllowedToAct", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpAppLocker", format!("{}/{}.exe", net45_path, tool));
    sharp_collection.insert("SharpBlock", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpChisel", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpChrome", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpChromium", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpCloud", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpCrashEventLog", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpDir", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpDoor", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpDPAPI", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpDump", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("sharpfiles", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpGPOAbuse", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpHandler", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpHose", format!("{}/{}.exe", net45_path, tool));
    sharp_collection.insert("SharpHound3", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpKatz", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpLAPS", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpMapExec", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpMiniDump", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpMove", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpRDP", format!("{}/{}.exe", net45_path, tool));
    sharp_collection.insert("SharpReg", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpSecDump", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpShares", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("Sharp-SMBExec", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpSphere", format!("{}/{}.exe", net45_path, tool));
    sharp_collection.insert("SharpSpray", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpStay", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpSvc", format!("{}/{}.exe", net47_path, tool));
    sharp_collection.insert("SharpTask", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpUp", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpView", format!("{}/{}.exe", net45_path, tool));
    sharp_collection.insert("SharpWMI", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SharpZeroLogon", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("Shhmon", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("Snaffler", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SqlClient", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("StandIn", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("StickyNotesExtract", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("SweetPotato", format!("{}/{}.exe", net45_path, tool));
    sharp_collection.insert("ThunderFox", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("TruffleSnout", format!("{}/{}.exe", net45_path, tool));
    sharp_collection.insert("Watson", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("winPEAS", format!("{}/{}.exe", net40_path, tool));
    sharp_collection.insert("WMIReg", format!("{}/{}.exe", net40_path, tool));
    // check if path exists
    let full_path = match sharp_collection.get(tool.as_str()) {
        Some(full_path) => full_path.to_string(),
        None => return "".to_string(),
    };
    if fs::metadata(full_path.clone()).is_err() {
        return "".to_string();
    }
    full_path
}

pub fn create_link_dir() {
    let home_dir = match std::env::var("HOME") {
        Err(e) => {
            println!("{}", e);
            return;
        }
        Ok(home) => home,
    };
    let link_dir = format!("{}/.link", home_dir);
    if fs::metadata(link_dir.as_str()).is_ok() {
        return;
    }
    match fs::create_dir_all(link_dir.as_str()) {
        Err(e) => {
            println!("{}", e);
        }
        Ok(home) => home,
    }
}
pub fn git_exists() -> bool {
    if std::process::Command::new("git")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_err()
    {
        println!("git not installed");
        return false;
    }
    true
}

fn update_sharpcollection() {
    if !git_exists() {
        println!("could not download SharpCollection");
        return;
    }
    let home_dir = match std::env::var("HOME") {
        Err(e) => {
            println!("{}", e);
            return;
        }
        Ok(home) => home,
    };
    let link_path = format!("{}/.link", home_dir);
    let sharpcollection_path = format!("{}/3rdparty/SharpCollection", link_path);
    let prev_dir_path = std::env::current_dir().unwrap();
    if std::env::set_current_dir(sharpcollection_path).is_err() {
        println!("could not change directory");
        return;
    }
    println!("updating SharpCollection");
    let output = std::process::Command::new("git").args(&["pull"]).output();
    match output {
        Err(_) => println!("could not update"),
        Ok(_) => println!("updated"),
    }
    // return to previous path
    if std::env::set_current_dir(prev_dir_path).is_err() {
        println!("could not change back to previous directory");
    }
}

fn download_sharpcollection() {
    if !git_exists() {
        println!("could not download SharpCollection");
        return;
    }
    let home_dir = match std::env::var("HOME") {
        Err(e) => {
            println!("{}", e);
            return;
        }
        Ok(home) => home,
    };
    let link_path = format!("{}/.link", home_dir);
    let third_party_path = format!("{}/3rdparty", link_path);
    let sharpcollection_path = format!("{}/3rdparty/SharpCollection", link_path);
    if fs::metadata(sharpcollection_path.as_str()).is_ok() {
        update_sharpcollection();
        return;
    }
    match fs::create_dir_all(third_party_path.as_str()) {
        Err(e) => {
            println!("{}", e);
        }
        Ok(third) => third,
    }
    let prev_dir_path = std::env::current_dir().unwrap();
    if std::env::set_current_dir(third_party_path).is_err() {
        println!("could not change directory");
        return;
    }
    println!("downloading SharpCollection");
    let _ = std::process::Command::new("git")
        .args(&["clone", "https://github.com/Flangvik/SharpCollection"])
        .output();
    if fs::metadata(sharpcollection_path.as_str()).is_ok() {
        println!("downloaded");
    }
    // return to previous path
    if std::env::set_current_dir(prev_dir_path).is_err() {
        println!("could not change back to previous directory");
    }
}

pub fn sharpcollection_manage(command: Vec<String>) {
    if command.len() < 2 {
        sharp_help();
        return;
    }
    if command[1] == *"init" {
        download_sharpcollection();
        return;
    }
    sharp_help();
}

fn sharp_help() {
    println!("sharp");
    println!("  sharp init  download/update SharpCollection tools");
}

pub fn sharp_link_help() {
    println!("sharp commands:");
    println!("  sharp ADCollector                 C# tool to quickly extract valuable information from the Active Directory environment @dev-2null");
    println!("  sharp ADSearch                    C# tool to help query AD via the LDAP protocol @tomcarver16 (Only NET 4.7)");
    println!(
        "  sharp AtYourService               C# .NET Assembly for Service Enumeration @mitchmoser"
    );
    println!("  sharp BetterSafetyKatz            Fork of SafetyKatz dynamically fetches the latest Mimikatz, runtime patching signatures and PE loads Mimikatz into memory. @Flangvik");
    println!("  sharp Grouper2                    C# tool to help find security-related misconfigurations in Active Directory Group Policy. @mikeloss");
    println!("  sharp InveighZero                 Windows C# LLMNR/mDNS/NBNS/DNS/DHCPv6 spoofer/man-in-the-middle tool . @Kevin-Robertson");
    println!(
        "  sharp LockLess                    Allows for the copying of locked files. @GhostPack"
    );
    println!("  sharp PurpleSharp                 C# adversary simulation tool that executes adversary techniques with the purpose of generating attack telemetry in monitored Windows environments. @mvelazc0");
    println!("  sharp Rubeus                      C# toolset for raw Kerberos interaction and abuses. @GhostPack");
    println!("  sharp SafetyKatz                  Combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's .NET PE Loader. @GhostPack");
    println!("  sharp SauronEye                   C# search tool find specific files containing specific keywords (.doc, .docx, .xls, .xlsx). @_vivami");
    println!("  sharp scout                       A .NET assembly for performing recon against hosts on a network . @jaredhaight");
    println!("  sharp SearchOutlook               C# tool to search through a running instance of Outlook for keywords @RedLectroid");
    println!("  sharp Seatbelt                    Performs a number of security oriented host-survey \"safety checks\". @GhostPack");
    println!("  sharp SharpAllowedToAct           C# implementation of a computer object takeover through Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) @pkb1s @leechristensen");
    println!("  sharp SharpAppLocker              C# port of the Get-AppLockerPolicy PS cmdlet with extended features @Flangvik");
    println!("  sharp SharpBlock                  A method of bypassing EDR's active projection DLL's by preventing entry point exection. @CCob");
    println!("  sharp SharpChisel                 C# Chisel Wrapper. @shantanu561993");
    println!("  sharp SharpChrome                 Chrome-specific implementation of SharpDPAPI capable of cookies and logins decryption/triage. @GhostPack");
    println!("  sharp SharpChromium               C# Project to retrieve Chromium data, such as cookies, history and saved logins. @djhohnstein");
    println!("  sharp SharpCloud                  Simple C# for checking for the existence of credential files related to AWS, Microsoft Azure, and Google Compute. @chrismaddalena");
    println!("  sharp SharpCrashEventLog          C# port of LogServiceCrash @slyd0g @limbenjamin");
    println!("  sharp SharpDir                    C# tool to search both local and remote file systems for files. @jnqpblc");
    println!("  sharp SharpDoor                   C# tool to allow multiple RDP (Remote Desktop) sessions by patching termsrv.dll file. @infosecn1nja");
    println!("  sharp SharpDPAPI                  C# port of some Mimikatz DPAPI functionality. @GhostPack");
    println!("  sharp SharpDump                   SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality. @GhostPack");
    println!("  sharp sharpfiles                  C# tool to search for files based on SharpShares output. @fullmetalcache");
    println!("  sharp SharpGPOAbuse               SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO). @FSecureLABS");
    println!("  sharp SharpHandler                C# tool for stealing/duping handles to LSASS @Jean_Maes_1994");
    println!("  sharp SharpHose                   Asynchronous Password Spraying Tool in C# for Windows Environments . @ustayready");
    println!(
        "  sharp SharpHound3                 C# Rewrite of the BloodHound Ingestor. @BloodHoundAD"
    );
    println!("  sharp SharpKatz                   PURE C# port of significant MimiKatz functionality such as logonpasswords, dcsync, etc. @b4rtik");
    println!("  sharp SharpLAPS                   A C# tool to retrieve LAPS passwords from LDAP @pentest_swissky");
    println!("  sharp SharpMapExec                C# version of @byt3bl33d3r's tool CrackMapExec @cube0x0");
    println!("  sharp SharpMiniDump               C# tool to Create a minidump of the LSASS process from memory @b4rtik");
    println!("  sharp SharpMove                   C# tool for performing lateral movement techniques @0xthirteen");
    println!("  sharp SharpRDP                    C# Remote Desktop Protocol Console Application for Authenticated Command Execution @0xthirteen");
    println!("  sharp SharpReg                    C# tool to interact with the Remote Registry service api. @jnqpblc");
    println!("  sharp SharpSecDump                C# port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py @G0ldenGunSec");
    println!("  sharp SharpShares                 Enumerate all network shares in the current domain. @djhohnstein");
    println!("  sharp Sharp-SMBExec               A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script @checkymander");
    println!("  sharp SharpSphere                 C# SharpSphere has the ability to interact with the guest operating systems of virtual machines managed by vCenter. @jkcoote & @grzryc");
    println!("  sharp SharpSpray                  C# tool to perform a password spraying attack against all users of a domain using LDAP. @jnqpblc");
    println!(
        "  sharp SharpStay                   .NET project for installing Persistence. @0xthirteen"
    );
    println!("  sharp SharpSvc                    C# tool to interact with the SC Manager API. @jnqpblc (Only NET 4.7)");
    println!("  sharp SharpTask                   C# tool to interact with the Task Scheduler service api. @jnqpblc");
    println!(
        "  sharp SharpUp                     C# port of various PowerUp functionality. @GhostPack"
    );
    println!("  sharp SharpView                   C# implementation of harmj0y's PowerView. @tevora-threat");
    println!("  sharp SharpWMI                    C# implementation of various WMI functionality. @GhostPack");
    println!("  sharp SharpZeroLogon              C# port of CVE-2020-1472 , a.k.a. Zerologon. @buffaloverflow");
    println!("  sharp Shhmon                      Neutering Sysmon via driver unload. @Shhmon");
    println!("  sharp Snaffler                    C# tool for pentesters to help find delicious candy needles (creds mostly, but it's flexible). @SnaffCon");
    println!("  sharp SqlClient                   C# .NET mssql client for accessing database data through beacon. @FortyNorthSecurity");
    println!(
        "  sharp StandIn                     C# based small AD post-compromise toolkit. @FuzzySec"
    );
    println!("  sharp StickyNotesExtract          C# tool that extracts data from the Windows Sticky Notes database. @V1V1");
    println!("  sharp SweetPotato                 Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019 . @CCob");
    println!("  sharp ThunderFox                  C# Retrieves data (contacts, emails, history, cookies and credentials) from Thunderbird and Firefox. @V1V1");
    println!("  sharp TruffleSnout                C# based iterative AD discovery toolkit for offensive operators. @dsnezhkov");
    println!("  sharp Watson                      Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities . @rasta-mouse");
    println!("  sharp winPEAS                     PEASS Privilege Escalation Awesome Scripts (winPEAS). @carlospolop");
    println!("  sharp WMIReg                      C# PoC to interact with local/remote registry hives through WMI. @airzero24");
    println!("\n  sharp <process> <tool> <parameters>");
    println!("    eg: sharp svchost SharpKatz --Command logonpasswords");
}
