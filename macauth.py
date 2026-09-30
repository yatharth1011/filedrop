"""Checks a macOS account password through PAM (the `checkpw` service, which
exists for exactly this), in-process via ctypes -- so the password is never
put on a command line where other processes could see it, and nothing is
stored."""
import ctypes
import ctypes.util

PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_SUCCESS = 0


class _PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class _PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


_CONV_FUNC = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(_PamMessage)),
    ctypes.POINTER(ctypes.POINTER(_PamResponse)),
    ctypes.c_void_p,
)


class _PamConv(ctypes.Structure):
    _fields_ = [("conv", _CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]


_libpam = ctypes.CDLL(ctypes.util.find_library("pam"))
_libc = ctypes.CDLL(ctypes.util.find_library("c"))
_libc.calloc.restype = ctypes.c_void_p
_libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
_libc.strdup.restype = ctypes.c_void_p
_libc.strdup.argtypes = [ctypes.c_char_p]

_libpam.pam_start.restype = ctypes.c_int
_libpam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(_PamConv),
                              ctypes.POINTER(ctypes.c_void_p)]
_libpam.pam_authenticate.restype = ctypes.c_int
_libpam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
_libpam.pam_acct_mgmt.restype = ctypes.c_int
_libpam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
_libpam.pam_end.restype = ctypes.c_int
_libpam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]


def check_password(username, password, service="checkpw"):
    """True only if `password` is `username`'s macOS account password."""
    if not username or not password:
        return False
    secret = password.encode("utf-8")

    @_CONV_FUNC
    def conv(n_messages, messages, p_response, _appdata):
        # PAM owns (and frees) this array and each strdup'd answer.
        addr = _libc.calloc(n_messages, ctypes.sizeof(_PamResponse))
        if not addr:
            return 5  # PAM_BUF_ERR
        responses = ctypes.cast(addr, ctypes.POINTER(_PamResponse))
        for i in range(n_messages):
            if messages[i].contents.msg_style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                responses[i].resp = _libc.strdup(secret)
                responses[i].resp_retcode = 0
        p_response[0] = responses
        return PAM_SUCCESS

    handle = ctypes.c_void_p()
    conv_struct = _PamConv(conv, None)
    rc = _libpam.pam_start(service.encode(), username.encode(), ctypes.byref(conv_struct), ctypes.byref(handle))
    if rc != PAM_SUCCESS:
        return False
    rc = _libpam.pam_authenticate(handle, 0)
    if rc == PAM_SUCCESS:
        rc = _libpam.pam_acct_mgmt(handle, 0)
    _libpam.pam_end(handle, rc)
    return rc == PAM_SUCCESS

