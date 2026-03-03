import { useState, useRef } from 'react'
import { loadNotes, type DepositNote } from '../lib/privacy'

interface NoteBackupProps {
  notes: DepositNote[]
  onImport: () => void
}

/**
 * Encrypt notes with AES-256-GCM using an HKDF-derived key from the master key.
 * Returns base64-encoded iv || ciphertext.
 */
async function encryptBackup(plaintext: string, masterKey: bigint): Promise<string> {
  const mkBytes = new Uint8Array(32)
  let val = masterKey
  for (let i = 31; i >= 0; i--) {
    mkBytes[i] = Number(val & 0xffn)
    val >>= 8n
  }

  const keyMaterial = await crypto.subtle.importKey('raw', mkBytes, 'HKDF', false, ['deriveKey'])
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('2birds-backup-v1') },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  )

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext))

  // Format: salt(16) || iv(12) || ciphertext
  const combined = new Uint8Array(16 + 12 + ct.byteLength)
  combined.set(salt, 0)
  combined.set(iv, 16)
  combined.set(new Uint8Array(ct), 28)

  let binary = ''
  for (let i = 0; i < combined.length; i++) binary += String.fromCharCode(combined[i])
  return btoa(binary)
}

/**
 * Decrypt a backup file encrypted with encryptBackup.
 */
async function decryptBackup(encoded: string, masterKey: bigint): Promise<string> {
  const mkBytes = new Uint8Array(32)
  let val = masterKey
  for (let i = 31; i >= 0; i--) {
    mkBytes[i] = Number(val & 0xffn)
    val >>= 8n
  }

  const combined = Uint8Array.from(atob(encoded), c => c.charCodeAt(0))
  const salt = combined.slice(0, 16)
  const iv = combined.slice(16, 28)
  const ct = combined.slice(28)

  const keyMaterial = await crypto.subtle.importKey('raw', mkBytes, 'HKDF', false, ['deriveKey'])
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('2birds-backup-v1') },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  )

  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct)
  return new TextDecoder().decode(pt)
}

export function NoteBackup({ notes, onImport }: NoteBackupProps) {
  const [exporting, setExporting] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importResult, setImportResult] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  async function handleExport() {
    if (notes.length === 0) return
    setExporting(true)
    try {
      const { getCachedMasterKey } = await import('../lib/privacy')
      const mk = await getCachedMasterKey()
      if (!mk) throw new Error('Master key not available — unlock your wallet first')

      const backup = {
        version: 1,
        network: (await import('../lib/config')).NETWORK,
        timestamp: new Date().toISOString(),
        notes: notes.map(n => ({
          secret: n.secret.toString(),
          nullifier: n.nullifier.toString(),
          commitment: n.commitment.toString(),
          leafIndex: n.leafIndex,
          denomination: n.denomination.toString(),
          assetId: n.assetId,
          timestamp: n.timestamp,
          appId: n.appId,
        })),
      }

      const encrypted = await encryptBackup(JSON.stringify(backup), mk)
      const blob = new Blob([encrypted], { type: 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `2birds-backup-${new Date().toISOString().slice(0, 10)}.2birds`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Export failed:', err)
    } finally {
      setExporting(false)
    }
  }

  async function handleImport(file: File) {
    setImporting(true)
    setImportResult(null)
    try {
      const { getCachedMasterKey, saveNote } = await import('../lib/privacy')
      const mk = await getCachedMasterKey()
      if (!mk) throw new Error('Master key not available — unlock your wallet first')

      const encoded = await file.text()
      const json = await decryptBackup(encoded, mk)
      const backup = JSON.parse(json)

      if (backup.version !== 1) throw new Error(`Unknown backup version: ${backup.version}`)

      const existingNotes = await loadNotes()
      const existingCommitments = new Set(existingNotes.map(n => n.commitment.toString()))

      let imported = 0
      for (const n of backup.notes) {
        const commitment = BigInt(n.commitment)
        if (existingCommitments.has(commitment.toString())) continue

        await saveNote({
          secret: BigInt(n.secret),
          nullifier: BigInt(n.nullifier),
          commitment,
          leafIndex: n.leafIndex,
          denomination: BigInt(n.denomination),
          assetId: n.assetId,
          timestamp: n.timestamp,
          appId: n.appId,
        })
        imported++
      }

      setImportResult(imported > 0
        ? `Imported ${imported} note${imported > 1 ? 's' : ''}`
        : 'All notes already present')
      onImport()
    } catch (err: any) {
      setImportResult(`Import failed: ${err?.message || 'Unknown error'}`)
    } finally {
      setImporting(false)
    }
  }

  return (
    <div className="note-backup">
      <div className="note-backup__header">Backup</div>

      <div className="note-backup__actions">
        <button
          className="manage-btn manage-btn--recover"
          onClick={handleExport}
          disabled={exporting || notes.length === 0}
          style={{ flex: 1 }}
        >
          {exporting ? 'Encrypting...' : `Export ${notes.length} note${notes.length !== 1 ? 's' : ''}`}
        </button>

        <button
          className="manage-btn manage-btn--recover"
          onClick={() => fileInputRef.current?.click()}
          disabled={importing}
          style={{ flex: 1 }}
        >
          {importing ? 'Decrypting...' : 'Import backup'}
        </button>

        <input
          ref={fileInputRef}
          type="file"
          accept=".2birds"
          style={{ display: 'none' }}
          onChange={e => {
            const file = e.target.files?.[0]
            if (file) handleImport(file)
            e.target.value = ''
          }}
        />
      </div>

      {importResult && (
        <div className="note-backup__result">{importResult}</div>
      )}

      <div className="note-backup__hint">
        Encrypted with your master key. Keep the .2birds file safe — it's your backup if you lose browser data.
      </div>
    </div>
  )
}
