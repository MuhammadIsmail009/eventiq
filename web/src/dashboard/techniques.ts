export interface TechniqueInfo {
  tactic: string
  name: string
}

export const TECHNIQUE_INFO: Record<string, TechniqueInfo> = {
  T1046: { tactic: 'Discovery', name: 'Network Service Discovery' },
  'T1110.001': { tactic: 'Credential Access', name: 'Password Guessing' },
  'T1110.003': { tactic: 'Credential Access', name: 'Password Spraying' },
  T1021: { tactic: 'Lateral Movement', name: 'Remote Services' },
  'T1059.001': { tactic: 'Execution', name: 'PowerShell' },
  'T1071.004': { tactic: 'Command and Control', name: 'DNS' },
  T1105: { tactic: 'Command and Control', name: 'Ingress Tool Transfer' },
  T1571: { tactic: 'Command and Control', name: 'Non-Standard Port' },
}

export const TACTIC_ORDER = [
  'Discovery',
  'Credential Access',
  'Lateral Movement',
  'Execution',
  'Command and Control',
  'Unmapped',
] as const

export function techniqueInfo(id: string): TechniqueInfo {
  return TECHNIQUE_INFO[id] ?? { tactic: 'Unmapped', name: id }
}
