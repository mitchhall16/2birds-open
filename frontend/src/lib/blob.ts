// Metaball liquid blob rendering engine
// Multi-color deposits, mouse interaction, streaming particles

interface Blob {
  x: number
  y: number
  r: number
  vx: number
  vy: number
  color: [number, number, number] // RGB
}

interface StreamParticle {
  x: number
  y: number
  r: number
  vx: number
  vy: number
  alpha: number
  color: [number, number, number]
  trail: { x: number; y: number }[]
  phase: 'streaming' | 'merging' | 'leaving'
}

export interface BlobEngine {
  render: () => void
  setPoolBalance: (algo: number) => void
  triggerDeposit: () => void
  triggerWithdraw: () => void
  destroy: () => void
}

// Palette of vibrant colors that look good on dark backgrounds
const COLOR_PALETTE: [number, number, number][] = [
  [0, 212, 170],    // teal (base)
  [0, 180, 255],    // cyan
  [120, 100, 255],  // violet
  [255, 100, 180],  // pink
  [0, 255, 140],    // mint
  [255, 180, 0],    // amber
  [100, 220, 255],  // sky
  [220, 80, 255],   // magenta
  [80, 255, 200],   // seafoam
  [255, 120, 80],   // coral
]

function randomColor(): [number, number, number] {
  return COLOR_PALETTE[Math.floor(Math.random() * COLOR_PALETTE.length)]
}

function lerpColor(
  a: [number, number, number],
  b: [number, number, number],
  t: number
): [number, number, number] {
  return [
    Math.round(a[0] + (b[0] - a[0]) * t),
    Math.round(a[1] + (b[1] - a[1]) * t),
    Math.round(a[2] + (b[2] - a[2]) * t),
  ]
}

// How many metaball sources for a given pool balance
function getBlobTarget(balance: number): number {
  if (balance <= 0) return 4
  // Each ~0.1 ALGO adds a blob, capped at 40
  return Math.max(4, Math.min(Math.floor(4 + balance * 10), 40))
}

export function createBlobEngine(canvas: HTMLCanvasElement): BlobEngine {
  const ctx = canvas.getContext('2d')!

  let width = 0
  let height = 0
  let animId = 0
  let poolBalance = 0
  let targetRadius = 30

  // Mouse state
  let mouseX = -1000
  let mouseY = -1000
  let mouseActive = false

  // Metaball sources — each has its own color
  const blobs: Blob[] = []
  let lastBlobTarget = 0

  // Streaming particles (deposits coming in, withdrawals going out)
  const particles: StreamParticle[] = []

  // Track colors that have been mixed in
  const mixedColors: [number, number, number][] = [[0, 212, 170]]

  function resize() {
    width = window.innerWidth
    height = window.innerHeight
    canvas.width = width
    canvas.height = height
    canvas.style.width = `${width}px`
    canvas.style.height = `${height}px`
  }

  function initBlobs() {
    blobs.length = 0
    const cx = width / 2
    const cy = height / 2
    const count = getBlobTarget(poolBalance)
    lastBlobTarget = count
    for (let i = 0; i < count; i++) {
      const angle = (Math.PI * 2 * i) / count
      const dist = 10 + Math.random() * 15
      blobs.push({
        x: cx + Math.cos(angle) * dist,
        y: cy + Math.sin(angle) * dist,
        r: 15 + Math.random() * 10,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        color: mixedColors[i % mixedColors.length] || [0, 212, 170],
      })
    }
  }

  function updateBlobs() {
    const cx = width / 2
    const cy = height / 2
    const sizeScale = targetRadius / 60
    // More blobs → smaller individual blobs (normalized to 6 as baseline)
    const blobCount = blobs.length || 1
    const perBlobScale = Math.sqrt(6 / blobCount)

    for (const b of blobs) {
      // Drift
      b.x += b.vx
      b.y += b.vy

      // Pull toward center — gentle spring
      const dx = cx - b.x
      const dy = cy - b.y
      const dist = Math.sqrt(dx * dx + dy * dy)
      const maxDrift = 40 + targetRadius * 0.5
      // Soft constant pull
      b.vx += dx * 0.0004
      b.vy += dy * 0.0004
      // Stronger pull when far out
      if (dist > maxDrift) {
        b.vx += (dx / dist) * 0.06
        b.vy += (dy / dist) * 0.06
      }

      // Mouse repulsion — gentle nudge
      if (mouseActive) {
        const mx = b.x - mouseX
        const my = b.y - mouseY
        const mDist = Math.sqrt(mx * mx + my * my)
        const pushRadius = targetRadius * 1.0 + 50
        if (mDist < pushRadius && mDist > 1) {
          const force = (1 - mDist / pushRadius) * 0.4
          b.vx += (mx / mDist) * force
          b.vy += (my / mDist) * force
        }
      }

      // Damping
      b.vx *= 0.995
      b.vy *= 0.995

      // Random perturbation — organic drifting
      b.vx += (Math.random() - 0.5) * 0.15
      b.vy += (Math.random() - 0.5) * 0.15

      // Smooth size — per-blob scale keeps individual blobs smaller when there are many
      const targetR = (18 + Math.random() * 0.5) * sizeScale * perBlobScale
      b.r += (targetR - b.r) * 0.08

      // Each blob keeps its own color — no blending
    }
  }

  function updateParticles() {
    for (let i = particles.length - 1; i >= 0; i--) {
      const p = particles[i]

      // Save trail position
      p.trail.push({ x: p.x, y: p.y })
      if (p.trail.length > 20) p.trail.shift()

      if (p.phase === 'streaming') {
        // Move toward center
        const cx = width / 2
        const cy = height / 2
        const dx = cx - p.x
        const dy = cy - p.y
        const dist = Math.sqrt(dx * dx + dy * dy)

        if (dist < targetRadius * 0.4 + 10) {
          p.phase = 'merging'
        } else {
          // Accelerate toward center with slight curve
          const speed = 3 + (1 - dist / (width * 0.6)) * 4
          p.vx += (dx / dist) * 0.3
          p.vy += (dy / dist) * 0.3
          const v = Math.sqrt(p.vx * p.vx + p.vy * p.vy)
          if (v > speed) {
            p.vx = (p.vx / v) * speed
            p.vy = (p.vy / v) * speed
          }
          p.x += p.vx
          p.y += p.vy
        }
      } else if (p.phase === 'merging') {
        // Shrink and fade into the blob
        p.alpha -= 0.04
        p.r *= 0.95
        if (p.alpha <= 0) {
          particles.splice(i, 1)
          continue
        }
      } else if (p.phase === 'leaving') {
        // Accelerate outward
        p.x += p.vx
        p.y += p.vy
        p.vx *= 1.03
        p.vy *= 1.03
        p.alpha -= 0.018
        p.r *= 0.985

        if (p.alpha <= 0 || p.x < -50 || p.x > width + 50 || p.y < -50 || p.y > height + 50) {
          particles.splice(i, 1)
          continue
        }
      }
    }
  }

  function renderField() {
    if (poolBalance <= 0 && particles.length === 0) {
      // Empty pool — render a dim ring
      const cx = width / 2
      const cy = height / 2
      ctx.beginPath()
      ctx.arc(cx, cy, 40, 0, Math.PI * 2)
      ctx.strokeStyle = '#ffffff08'
      ctx.lineWidth = 1
      ctx.stroke()

      ctx.font = '500 11px "IBM Plex Sans"'
      ctx.fillStyle = '#ffffff15'
      ctx.textAlign = 'center'
      ctx.fillText('Empty Pool', cx, cy + 4)
      return
    }

    // Render metaball field using pixel sampling with per-blob color blending
    const step = 3
    const threshold = 1.0

    const imgData = ctx.createImageData(width, height)
    const data = imgData.data

    for (let py = 0; py < height; py += step) {
      for (let px = 0; px < width; px += step) {
        let sum = 0
        let cr = 0, cg = 0, cb = 0
        let weightSum = 0

        for (const b of blobs) {
          const dx = px - b.x
          const dy = py - b.y
          const distSq = dx * dx + dy * dy
          const influence = (b.r * b.r) / distSq
          sum += influence

          if (influence > 0.1) {
            cr += b.color[0] * influence
            cg += b.color[1] * influence
            cb += b.color[2] * influence
            weightSum += influence
          }
        }

        if (weightSum > 0) {
          cr /= weightSum
          cg /= weightSum
          cb /= weightSum
        }

        if (sum >= threshold) {
          const intensity = Math.min(sum - threshold, 1.5) / 1.5
          const alpha = Math.floor(140 + intensity * 80)

          for (let sy = 0; sy < step && py + sy < height; sy++) {
            for (let sx = 0; sx < step && px + sx < width; sx++) {
              const idx = ((py + sy) * width + (px + sx)) * 4
              data[idx] = cr
              data[idx + 1] = cg
              data[idx + 2] = cb
              data[idx + 3] = alpha
            }
          }
        } else if (sum >= threshold * 0.6) {
          const edgeAlpha = Math.floor(((sum - threshold * 0.6) / (threshold * 0.4)) * 40)
          for (let sy = 0; sy < step && py + sy < height; sy++) {
            for (let sx = 0; sx < step && px + sx < width; sx++) {
              const idx = ((py + sy) * width + (px + sx)) * 4
              data[idx] = cr
              data[idx + 1] = cg
              data[idx + 2] = cb
              data[idx + 3] = edgeAlpha
            }
          }
        }
      }
    }

    ctx.putImageData(imgData, 0, 0)

    // Inner glow
    const cx = width / 2
    const cy = height / 2
    const avgColor = blobs.length > 0
      ? blobs.reduce((acc, b) => [acc[0] + b.color[0], acc[1] + b.color[1], acc[2] + b.color[2]], [0, 0, 0]).map(c => Math.round(c / blobs.length))
      : [0, 212, 170]
    const glowR = targetRadius * 0.7
    const glow = ctx.createRadialGradient(cx - glowR * 0.2, cy - glowR * 0.3, 0, cx, cy, targetRadius * 1.2)
    glow.addColorStop(0, `rgba(${avgColor[0]}, ${avgColor[1]}, ${avgColor[2]}, 0.1)`)
    glow.addColorStop(0.5, `rgba(${avgColor[0]}, ${avgColor[1]}, ${avgColor[2]}, 0.03)`)
    glow.addColorStop(1, 'transparent')
    ctx.fillStyle = glow
    ctx.fillRect(0, 0, width, height)
  }

  function renderParticles() {
    for (const p of particles) {
      const [r, g, b] = p.color

      // Draw trail
      if (p.trail.length > 2) {
        ctx.beginPath()
        ctx.moveTo(p.trail[0].x, p.trail[0].y)
        for (let i = 1; i < p.trail.length; i++) {
          ctx.lineTo(p.trail[i].x, p.trail[i].y)
        }
        ctx.lineTo(p.x, p.y)
        const trailAlpha = p.alpha * 0.4
        ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${trailAlpha})`
        ctx.lineWidth = p.r * 0.6
        ctx.lineCap = 'round'
        ctx.lineJoin = 'round'
        ctx.stroke()
      }

      // Draw particle
      ctx.beginPath()
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
      ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${p.alpha})`
      ctx.fill()

      // Glow
      const glow = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r * 2.5)
      glow.addColorStop(0, `rgba(${r}, ${g}, ${b}, ${p.alpha * 0.25})`)
      glow.addColorStop(1, 'transparent')
      ctx.fillStyle = glow
      ctx.fillRect(p.x - p.r * 3, p.y - p.r * 3, p.r * 6, p.r * 6)
    }
  }

  function frame() {
    ctx.clearRect(0, 0, width, height)

    // Smooth target radius toward pool balance — scale to viewport
    const minDim = Math.min(width, height)
    // Linear scale, caps at 30% of viewport
    const maxRadius = minDim * 0.3
    const desiredRadius = poolBalance > 0
      ? Math.min(8 + poolBalance * 1.0, maxRadius)
      : 0
    targetRadius += (desiredRadius - targetRadius) * 0.08

    // Dynamically add/remove blobs based on pool balance
    const blobTarget = getBlobTarget(poolBalance)
    if (blobTarget !== lastBlobTarget) {
      const cx = width / 2
      const cy = height / 2
      while (blobs.length < blobTarget) {
        const angle = Math.random() * Math.PI * 2
        const dist = 5 + Math.random() * 15
        blobs.push({
          x: cx + Math.cos(angle) * dist,
          y: cy + Math.sin(angle) * dist,
          r: 1, // start small, will grow
          vx: (Math.random() - 0.5) * 0.4,
          vy: (Math.random() - 0.5) * 0.4,
          color: mixedColors[Math.floor(Math.random() * mixedColors.length)] || [0, 212, 170],
        })
      }
      while (blobs.length > blobTarget) {
        blobs.pop()
      }
      lastBlobTarget = blobTarget
    }

    updateBlobs()
    updateParticles()

    renderField()
    renderParticles()

    animId = requestAnimationFrame(frame)
  }

  // Mouse event handlers
  function onMouseMove(e: MouseEvent) {
    const rect = canvas.getBoundingClientRect()
    mouseX = e.clientX - rect.left
    mouseY = e.clientY - rect.top
    mouseActive = true
  }

  function onMouseLeave() {
    mouseActive = false
    mouseX = -1000
    mouseY = -1000
  }

  function onTouchMove(e: TouchEvent) {
    if (e.touches.length > 0) {
      const rect = canvas.getBoundingClientRect()
      mouseX = e.touches[0].clientX - rect.left
      mouseY = e.touches[0].clientY - rect.top
      mouseActive = true
    }
  }

  function onTouchEnd() {
    mouseActive = false
    mouseX = -1000
    mouseY = -1000
  }

  // Initialize
  resize()
  initBlobs()
  animId = requestAnimationFrame(frame)

  const resizeHandler = () => resize()
  window.addEventListener('resize', resizeHandler)
  canvas.addEventListener('mousemove', onMouseMove)
  canvas.addEventListener('mouseleave', onMouseLeave)
  canvas.addEventListener('touchmove', onTouchMove, { passive: true })
  canvas.addEventListener('touchend', onTouchEnd)

  return {
    render: frame,

    setPoolBalance(algo: number) {
      poolBalance = algo
    },

    triggerDeposit() {
      // Pick a random color and direction
      const color = randomColor()
      mixedColors.push(color)
      // Keep only recent colors for blending
      if (mixedColors.length > 12) mixedColors.shift()

      // Assign the new color to a random blob
      if (blobs.length > 0) {
        const idx = Math.floor(Math.random() * blobs.length)
        blobs[idx].color = color
      }

      // Spawn streaming particle from a random edge
      const angle = Math.random() * Math.PI * 2
      const spawnDist = Math.max(width, height) * 0.6
      const cx = width / 2
      const cy = height / 2

      particles.push({
        x: cx + Math.cos(angle) * spawnDist,
        y: cy + Math.sin(angle) * spawnDist,
        r: 10 + Math.random() * 5,
        vx: 0,
        vy: 0,
        alpha: 1,
        color,
        trail: [],
        phase: 'streaming',
      })
    },

    triggerWithdraw() {
      // Eject a piece from the center in a random direction
      const angle = Math.random() * Math.PI * 2
      const cx = width / 2
      const cy = height / 2
      const speed = 2 + Math.random() * 2

      // Use a color from the current mix
      const color = blobs.length > 0
        ? [...blobs[Math.floor(Math.random() * blobs.length)].color] as [number, number, number]
        : [0, 212, 170] as [number, number, number]

      particles.push({
        x: cx + Math.cos(angle) * (targetRadius * 0.3),
        y: cy + Math.sin(angle) * (targetRadius * 0.3),
        r: 8 + Math.random() * 4,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        alpha: 1,
        color,
        trail: [],
        phase: 'leaving',
      })
    },

    destroy() {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', resizeHandler)
      canvas.removeEventListener('mousemove', onMouseMove)
      canvas.removeEventListener('mouseleave', onMouseLeave)
      canvas.removeEventListener('touchmove', onTouchMove)
      canvas.removeEventListener('touchend', onTouchEnd)
    },
  }
}
