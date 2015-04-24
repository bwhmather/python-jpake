class DuplicateSignerError(Exception):
    def __init__(self, signer_id):
        self.signer_id = signer_id

    def __str__(self):
        return (
            "Other party uses same signer id (%r).  To avoid replay attacks "
            "a different id is required for each end."
        ) % self.signer_id


class InvalidProofError(Exception):
    pass


class OutOfSequenceError(Exception):
    pass
