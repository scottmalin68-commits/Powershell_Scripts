<#
.SYNOPSIS
    Copies .md file content to the clipboard via a terminal menu.

.DESCRIPTION
    Working with AI prompts can be messy. This script makes it easy to 
    browse and grab your saved prompts or notes without opening files.
    It lists all .md files in the current folder, lets you pick one by 
    number, and loads it into your paste buffer.

.NOTES
    Author: Scott M.
    Date: 2026-02-24

.CHANGELOG
    v1.0 (2026-02-24) - Initial build.
    v1.1 (2026-02-24) - Switched from Out-GridView to console menu.
    v1.2 (2026-02-24) - Updated menu to start at 1, added 0 for exit.
#>

# find files
$files = Get-ChildItem -Filter *.md

if (-not $files) { 
    echo "no .md files found."
    Pause
    exit 
}

# show the menu
echo "`n--- prompt selector ---"
echo "[0] exit"

for ($i=0; $i -lt $files.Count; $i++) {
    $num = $i + 1
    echo "[$num] $($files[$i].Name)"
}

# get input
$choice = Read-Host "`nselect a number"

# handle choice
if ($choice -eq "0" -or -not $choice) {
    echo "cancelled."
    exit
}

# validate and copy
if ($choice -match '^\d+$' -and $choice -le $files.Count -and $choice -gt 0) {
    $index = [int]$choice - 1
    $target = $files[$index]
    
    Get-Content $target.FullName | Set-Clipboard
    echo "`nsuccess: $($target.Name) is now in your paste buffer."
} else {
    echo "`ninvalid choice. try again."
}

echo ""
Pause