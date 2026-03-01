import { useRef, useEffect } from 'react'
import { createBlobEngine, type BlobEngine } from '../lib/blob'

interface PoolBlobProps {
  poolBalance: number // in ALGO
  onDeposit?: boolean // triggers deposit animation
  onWithdraw?: boolean // triggers withdraw animation
}

export function PoolBlob({ poolBalance, onDeposit, onWithdraw }: PoolBlobProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const engineRef = useRef<BlobEngine | null>(null)
  const prevDeposit = useRef(false)
  const prevWithdraw = useRef(false)

  useEffect(() => {
    if (!canvasRef.current) return
    const engine = createBlobEngine(canvasRef.current)
    engineRef.current = engine
    return () => engine.destroy()
  }, [])

  useEffect(() => {
    engineRef.current?.setPoolBalance(poolBalance)
  }, [poolBalance])

  useEffect(() => {
    if (onDeposit && !prevDeposit.current) {
      engineRef.current?.triggerDeposit()
    }
    prevDeposit.current = !!onDeposit
  }, [onDeposit])

  useEffect(() => {
    if (onWithdraw && !prevWithdraw.current) {
      engineRef.current?.triggerWithdraw()
    }
    prevWithdraw.current = !!onWithdraw
  }, [onWithdraw])

  return (
    <div className="pool-canvas-wrap">
      <canvas ref={canvasRef} />
    </div>
  )
}
