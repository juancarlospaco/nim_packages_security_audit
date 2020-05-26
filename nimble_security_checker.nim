import os, strutils, json, osproc, times

const
  nimInstallCmd = "python3 tracexec.py /bin/bash init.sh -y --debug --noColor"
  checkCmd = "python3 tracexec.py nimble --noColor --verbose --accept install "
  packages = "https://raw.githubusercontent.com/nim-lang/packages/master/packages.json"
  jsn = staticExec("curl -s " & packages)

let serie = char(parseInt(now().format("d")) + 96)  # Do 1 "serie" per day of month.
var errors = "exitCode, name\n"


if serie >= 'z':  # if no packages to check, check Choosenim and init.sh
  if gorgeEx("curl -LOks https://nim-lang.org/choosenim/init.sh ; chmod +x init.sh").exitCode == 0:
    let audit = execCmdEx(nimInstallCmd)
    if audit.exitCode == 0: writeFile("nim_install.log", audit.output)
else:
  for item in parseJson(jsn).items:
    let name = item.getOrDefault("name").getStr.toLowerAscii
    let letter = $name[0]
    if unlikely(letter == $serie):
      let audit = execCmdEx(checkCmd & name)
      if audit.exitCode == 0:
        discard existsOrCreateDir(letter)
        let resultxt = letter / name & ".log"
        echo resultxt
        writeFile(resultxt, audit.output)
      else:
        errors.add $audit.exitCode & ", " & name & "\n"

writeFile("errors.csv.log", errors)
