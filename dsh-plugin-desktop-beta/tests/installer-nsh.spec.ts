import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { DESKTOP_INSTALLER_QUIT_FLAG } from '../src/desktop-installer-quit.ts'

describe('Windows NSIS running-app handoff', () => {
  it('checks for the exact app before requesting orderly shutdown', () => {
    const script = readFileSync(join(process.cwd(), 'build', 'installer.nsh'), 'utf8')
    const firstDetection = script.indexOf('!insertmacro FIND_PROCESS')
    const request = script.indexOf(DESKTOP_INSTALLER_QUIT_FLAG)
    const wait = script.indexOf('dsh_installer_wait_for_exit:')
    const fallback = script.indexOf('dsh_installer_scoped_fallback:')

    expect(script).toContain('!macro customCheckAppRunning')
    expect(script).toContain('Var pid')
    expect(script).toContain('ExecWait')
    expect(script).toContain('$INSTDIR\\${APP_EXECUTABLE_FILENAME}')
    expect(script).toContain('!insertmacro IS_POWERSHELL_AVAILABLE')
    expect(firstDetection).toBeGreaterThanOrEqual(0)
    expect(request).toBeGreaterThan(firstDetection)
    expect(wait).toBeGreaterThan(request)
    expect(fallback).toBeGreaterThan(wait)
  })

  it('waits for graceful disposal before using the scoped builder fallback', () => {
    const script = readFileSync(join(process.cwd(), 'build', 'installer.nsh'), 'utf8')

    expect(script).toContain('$R1 < 60')
    expect(script).toContain('Sleep 500')
    expect(script).toContain('!insertmacro KILL_PROCESS "${APP_EXECUTABLE_FILENAME}" 0')
    expect(script).toContain('!insertmacro KILL_PROCESS "${APP_EXECUTABLE_FILENAME}" 1')
    expect(script).not.toContain('taskkill')
    expect(script).not.toContain('nsProcess::KillProcess')
    expect(script).not.toContain('getProcessInfo.nsh')
  })
})

describe('Windows NSIS sandbox read access', () => {
  const customInstall = (): string => {
    const script = readFileSync(join(process.cwd(), 'build', 'installer.nsh'), 'utf8')
    const start = script.indexOf('!macro customInstall')
    expect(start).toBeGreaterThanOrEqual(0)
    const end = script.indexOf('!macroend', start)
    expect(end).toBeGreaterThan(start)
    return script.slice(start, end)
  }

  it('grants ALL RESTRICTED APPLICATION PACKAGES inheritable read access on the install root (#1366)', () => {
    const body = customInstall()

    // System icacls, not whatever icacls.exe happens to be on PATH.
    expect(body).toContain('"$SYSDIR\\icacls.exe" "$INSTDIR"')
    expect(body).toContain('/grant "*S-1-15-2-2:(OI)(CI)(RX)"')
    expect(body).toContain('nsExec::ExecToLog')
  })

  it('only adds read access and never blocks the install', () => {
    const body = customInstall()

    // One inheritable ACE on the root reaches every file; /T would stamp an
    // explicit copy onto each of the ~26k installed files instead.
    expect(body).not.toMatch(/\/T\b/)
    // Repair is additive: never reset or strip ACLs the user or another tool owns.
    expect(body).not.toMatch(/\/(reset|remove|deny|inheritance|setintegritylevel)\b/i)
    expect(body).not.toMatch(/\b(Abort|Quit)\b/)
    // The scratch register is restored for the builder code that follows.
    expect(body.indexOf('Push $0')).toBeLessThan(body.indexOf('nsExec::ExecToLog'))
    expect(body.trimEnd().endsWith('Pop $0')).toBe(true)
  })
})
