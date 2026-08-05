# Pure-Python modules that ship alongside the ngu C module.
# bip39.py is libngu's file, unchanged: its only crypto dependency is
# ngu.hash.pbkdf2_sha512, which this backend provides. Kept here so that
# external/libngu can be deleted entirely.
freeze_as_mpy('', [
    'bip39.py',
], opt=3)
