$timestamp = Get-Date -Format "yyyyMMddHHmmss"
New-Item -Path "C:\Test\encrypted_$timestamp.txt" -ItemType File -Value "Simulated ransomware payload" -Force