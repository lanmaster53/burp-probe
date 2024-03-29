class UserTypes:
    ADMIN = 'admin'
    USER = 'user'

class ScanStates:
    SUCCEEDED = 'succeeded'
    CANCELLED = 'cancelled'
    FAILED = 'failed'
    UNREACHABLE = 'unreachable'
    STARTED = 'started'
    CRAWLING = 'crawling'
    AUDITING = 'auditing'
    DEAD = [SUCCEEDED, CANCELLED, FAILED] # no need for further polling
    FINISHED = [SUCCEEDED, CANCELLED]
    ERROR = [FAILED, UNREACHABLE]
    ACTIVE = [STARTED, CRAWLING, AUDITING]
