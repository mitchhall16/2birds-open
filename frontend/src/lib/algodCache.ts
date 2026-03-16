import algosdk from 'algosdk'

const cache = new Map<string, { data: any; expiry: number }>()
const DEFAULT_TTL = 30_000 // 30 seconds

export async function cachedGetApp(client: algosdk.Algodv2, appId: number): Promise<any> {
  const key = `app:${appId}`
  const cached = cache.get(key)
  if (cached && Date.now() < cached.expiry) return cached.data
  const data = await client.getApplicationByID(appId).do()
  cache.set(key, { data, expiry: Date.now() + DEFAULT_TTL })
  return data
}

export async function cachedGetAccount(client: algosdk.Algodv2, addr: string): Promise<any> {
  const key = `acct:${addr}`
  const cached = cache.get(key)
  if (cached && Date.now() < cached.expiry) return cached.data
  const data = await client.accountInformation(addr).do()
  cache.set(key, { data, expiry: Date.now() + DEFAULT_TTL })
  return data
}

export function invalidateCache() { cache.clear() }
