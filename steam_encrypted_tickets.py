import ctypes
from ctypes import c_uint8, c_uint32, c_uint64, c_int, c_bool, POINTER
import platform

# Load the dynamic library
if platform.system() == 'Windows':
    steam_lib = ctypes.CDLL('./sdkencryptedappticket64.dll')
elif platform.system() == 'Linux':
    steam_lib = ctypes.CDLL('./libsdkencryptedappticket.so')

# Types
AppId_t = c_uint32
CSteamID = c_uint64
RTime32 = c_uint32

# Constants
TICKET_SIZE_BYTES = 1024
k_nSteamEncryptedAppTicketSymmetricKeyLen = 32 # this is in bytes, no worries :)

# Define argument and return types for each function
steam_lib.SteamEncryptedAppTicket_BDecryptTicket.argtypes = [
    POINTER(c_uint8), c_uint32, POINTER(c_uint8), POINTER(c_uint32), POINTER(c_uint8), c_int
]
steam_lib.SteamEncryptedAppTicket_BDecryptTicket.restype = c_bool

steam_lib.SteamEncryptedAppTicket_BIsTicketForApp.argtypes = [
    POINTER(c_uint8), c_uint32, AppId_t
]
steam_lib.SteamEncryptedAppTicket_BIsTicketForApp.restype = c_bool

steam_lib.SteamEncryptedAppTicket_GetTicketIssueTime.argtypes = [
    POINTER(c_uint8), c_uint32
]
steam_lib.SteamEncryptedAppTicket_GetTicketIssueTime.restype = RTime32

steam_lib.SteamEncryptedAppTicket_GetTicketSteamID.argtypes = [
    POINTER(c_uint8), c_uint32, POINTER(CSteamID)
]
steam_lib.SteamEncryptedAppTicket_GetTicketSteamID.restype = None

steam_lib.SteamEncryptedAppTicket_GetTicketAppID.argtypes = [
    POINTER(c_uint8), c_uint32
]
steam_lib.SteamEncryptedAppTicket_GetTicketAppID.restype = c_uint32

steam_lib.SteamEncryptedAppTicket_BUserOwnsAppInTicket.argtypes = [
    POINTER(c_uint8), c_uint32, AppId_t
]
steam_lib.SteamEncryptedAppTicket_BUserOwnsAppInTicket.restype = c_bool

steam_lib.SteamEncryptedAppTicket_BUserIsVacBanned.argtypes = [
    POINTER(c_uint8), c_uint32
]
steam_lib.SteamEncryptedAppTicket_BUserIsVacBanned.restype = c_bool

steam_lib.SteamEncryptedAppTicket_GetUserVariableData.argtypes = [
    POINTER(c_uint8), c_uint32, POINTER(c_uint32)
]
steam_lib.SteamEncryptedAppTicket_GetUserVariableData.restype = POINTER(c_uint8)


def bytes_to_c_uint8_array(bytes: bytes):
    return (ctypes.c_uint8 * len(bytes)).from_buffer_copy(bytes)

# Wrapper functions for ease of use
def decrypt_ticket(encrypted_ticket: bytes, key: bytes, key_length: int):
    decrypted_ticket = (ctypes.c_uint8 * TICKET_SIZE_BYTES)()
    decrypted_ticket_len = c_uint32(TICKET_SIZE_BYTES)
    if steam_lib.SteamEncryptedAppTicket_BDecryptTicket(
        bytes_to_c_uint8_array(encrypted_ticket), c_uint32(len(encrypted_ticket)), decrypted_ticket, ctypes.byref(decrypted_ticket_len), bytes_to_c_uint8_array(key), key_length
    ):
        return decrypted_ticket.raw[:decrypted_ticket_len.value]
    return None

def is_ticket_for_app(decrypted_ticket, app_id):
    return steam_lib.SteamEncryptedAppTicket_BIsTicketForApp(decrypted_ticket, len(decrypted_ticket), app_id)

def get_ticket_issue_time(decrypted_ticket):
    return steam_lib.SteamEncryptedAppTicket_GetTicketIssueTime(decrypted_ticket, len(decrypted_ticket))

def get_ticket_steam_id(decrypted_ticket):
    steam_id = CSteamID()
    steam_lib.SteamEncryptedAppTicket_GetTicketSteamID(decrypted_ticket, len(decrypted_ticket), ctypes.byref(steam_id))
    return steam_id.value

def get_ticket_app_id(decrypted_ticket):
    return steam_lib.SteamEncryptedAppTicket_GetTicketAppID(decrypted_ticket, len(decrypted_ticket))

def user_owns_app_in_ticket(decrypted_ticket, app_id):
    return steam_lib.SteamEncryptedAppTicket_BUserOwnsAppInTicket(decrypted_ticket, len(decrypted_ticket), app_id)

def user_is_vac_banned(decrypted_ticket):
    return steam_lib.SteamEncryptedAppTicket_BUserIsVacBanned(decrypted_ticket, len(decrypted_ticket))

def get_user_variable_data(decrypted_ticket):
    data_len = c_uint32()
    data = steam_lib.SteamEncryptedAppTicket_GetUserVariableData(decrypted_ticket, len(decrypted_ticket), ctypes.byref(data_len))
    return data[:data_len.value]


if __name__ == '__main__':
    # This spacewar key from the spacewar sources and Steamworks SDK documentation is actually invalid.
    # I asked steam support about it but got no answer whether it is supposed to be this way or is the key just outdated.
    # If you happen to know the spacewar key for encrypted tickets, please let me know.

    # You will need to replace it with the actual encrypted tickets secret key you get in your Developer Panel.
    # Keep in mind that since I don't have a valid decryption key yet, the code after decrypt_ticket was not tested.
    spacewar_key = bytes([0xed, 0x93, 0x86, 0x07, 0x36, 0x47, 0xce, 0xa5, 0x8b, 0x77, 0x21, 0x49, 0x0d, 0x59, 0xed, 0x44, 0x57, 0x23, 0xf0, 0xf6, 0x6e, 0x74, 0x14, 0xe1, 0x53, 0x3b, 0xa3, 0x3c, 0xd8, 0x03, 0xbd, 0xbd])
    assert len(spacewar_key) == k_nSteamEncryptedAppTicketSymmetricKeyLen
    encrypted_ticket = bytes.fromhex('abcdef1234')
    decrypted_ticket = decrypt_ticket(encrypted_ticket, spacewar_key, k_nSteamEncryptedAppTicketSymmetricKeyLen)
    if decrypted_ticket:
        app_id_in_ticket = get_ticket_app_id(decrypted_ticket)
        print(f"App ID in ticket: {app_id_in_ticket}")
    else:
        print("Failed to decrypt the ticket")
