// (pt-BR) Tipos de autenticação/armazenamento usados pelo Baileys.
// (pt-BR) Atualizado para incluir suporte a 'lid-mapping' no SignalDataTypeMap,
//         evitando duplicação de chaves quando a conversa alterna entre JID <-> LID.

import type { proto } from '../../WAProto'
import type { Contact } from './Contact'
import type { MinimalMessage } from './Message'

/** (pt-BR) Par de chaves público/privado para criptografia Signal */
export type KeyPair = { public: Uint8Array, private: Uint8Array }

/** (pt-BR) Par de chaves com assinatura + metadados */
export type SignedKeyPair = {
    keyPair: KeyPair
    signature: Uint8Array
    keyId: number
    timestampS?: number
}

/** (pt-BR) Endereço do protocolo Signal (jid + device) */
export type ProtocolAddress = {
    name: string // jid
    deviceId: number
}

/** (pt-BR) Identidade Signal (chave pública associada ao endereço) */
export type SignalIdentity = {
    identifier: ProtocolAddress
    identifierKey: Uint8Array
}

/** (pt-BR) Estado do hash incremental (usado no app state sync) */
export type LTHashState = {
    version: number
    hash: Buffer
    indexValueMap: {
        [indexMacBase64: string]: { valueMac: Uint8Array | Buffer }
    }
}

/** (pt-BR) Credenciais base do dispositivo */
export type SignalCreds = {
    readonly signedIdentityKey: KeyPair
    readonly signedPreKey: SignedKeyPair
    readonly registrationId: number
}

/** (pt-BR) Configurações da conta do WhatsApp */
export type AccountSettings = {
    /** unarchive chats when a new message is received */
    unarchiveChats: boolean
    /** the default mode to start new conversations with */
    defaultDisappearingMode?: Pick<proto.IConversation, 'ephemeralExpiration' | 'ephemeralSettingTimestamp'>
}

/** (pt-BR) Credenciais completas que o Baileys persiste para manter sessão */
export type AuthenticationCreds = SignalCreds & {
    readonly noiseKey: KeyPair
    readonly pairingEphemeralKeyPair: KeyPair
    advSecretKey: string

    me?: Contact
    account?: proto.IADVSignedDeviceIdentity
    signalIdentities?: SignalIdentity[]
    myAppStateKeyId?: string
    firstUnuploadedPreKeyId: number
    nextPreKeyId: number

    lastAccountSyncTimestamp?: number
    platform?: string

    processedHistoryMessages: MinimalMessage[]
    /** number of times history & app state has been synced */
    accountSyncCounter: number
    accountSettings: AccountSettings
    registered: boolean
    pairingCode: string | undefined
    lastPropHash: string | undefined
    routingInfo: Buffer | undefined
}

/**
 * (pt-BR) Mapa de tipos de dados persistidos no key store.
 * (pt-BR) IMPORTANTE: adicionamos 'lid-mapping' para suportar o mapeamento JID <-> LID
 *                     (presente a partir das correções 6.7.19+ / 7.x) e evitar chaves duplicadas.
 */
export type SignalDataTypeMap = {
    'pre-key': KeyPair
    'session': Uint8Array
    'sender-key': Uint8Array
    'sender-key-memory': { [jid: string]: boolean }
    'app-state-sync-key': proto.Message.IAppStateSyncKeyData
    'app-state-sync-version': LTHashState
    'lid-mapping': string // (pt-BR) mapeia IDs (ex.: LID -> JID ou vice-versa)
}

/** (pt-BR) Estrutura para setar múltiplos registros no key store de uma vez */
export type SignalDataSet = { [T in keyof SignalDataTypeMap]?: { [id: string]: SignalDataTypeMap[T] | null } }

/** (pt-BR) Awaitable simples para permitir sync/async */
type Awaitable<T> = T | Promise<T>

/** (pt-BR) Interface do armazenamento de chaves (get/set/clear) */
export type SignalKeyStore = {
    get<T extends keyof SignalDataTypeMap>(type: T, ids: string[]): Awaitable<{ [id: string]: SignalDataTypeMap[T] }>
    set(data: SignalDataSet): Awaitable<void>
    /** clear all the data in the store */
    clear?(): Awaitable<void>
}

/** (pt-BR) Key store com transações (opcional) */
export type SignalKeyStoreWithTransaction = SignalKeyStore & {
    isInTransaction: () => boolean
    transaction<T>(exec: () => Promise<T>): Promise<T>
}

/** (pt-BR) Opções de tentativa/retentativa de transação */
export type TransactionCapabilityOptions = {
    maxCommitRetries: number
    delayBetweenTriesMs: number
}

/** (pt-BR) Estado mínimo para inicializar a camada Signal */
export type SignalAuthState = {
    creds: SignalCreds
    keys: SignalKeyStore | SignalKeyStoreWithTransaction
}

/** (pt-BR) Estado completo de autenticação usado pelo socket */
export type AuthenticationState = {
    creds: AuthenticationCreds
    keys: SignalKeyStore
}
