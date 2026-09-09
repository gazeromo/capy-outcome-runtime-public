"""Safe account-setup observations, separate from permission and installation.

Only trusted custody/service code supplies these facts. This module accepts no
credentials, performs no provider transport, and never treats metadata as proof
of a usable account. Account-rate proof must concern the pending exact work.
"""
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class AccountReadiness:
    service: Literal['ready', 'unavailable', 'unknown'] = 'unknown'
    credentials: Literal['missing', 'present', 'unknown'] = 'unknown'
    authentication: Literal['unknown', 'accepted', 'rejected', 'pending'] = 'unknown'
    origin: Literal['missing', 'ready', 'unknown'] = 'unknown'
    quote: Literal['unknown', 'account_rates', 'list_rates', 'pending', 'rejected'] = 'unknown'

    def __post_init__(self):
        allowed = {
            'service': {'ready', 'unavailable', 'unknown'},
            'credentials': {'missing', 'present', 'unknown'},
            'authentication': {'unknown', 'accepted', 'rejected', 'pending'},
            'origin': {'missing', 'ready', 'unknown'},
            'quote': {'unknown', 'account_rates', 'list_rates', 'pending', 'rejected'},
        }
        for key, values in allowed.items():
            if getattr(self, key) not in values:
                # Do not include a supplied value in exceptions or logs.
                raise ValueError('Invalid account readiness observation')

    def public_status(self):
        if self.service != 'ready':
            status = 'service_unavailable' if self.service == 'unavailable' else 'readiness_pending'
        elif self.credentials == 'unknown':
            status = 'readiness_pending'
        elif self.credentials == 'missing':
            status = 'account_required'
        elif self.authentication == 'rejected':
            status = 'account_rejected'
        elif self.authentication != 'accepted':
            status = 'verification_pending'
        elif self.origin == 'missing':
            status = 'origin_required'
        elif self.origin != 'ready':
            status = 'readiness_pending'
        elif self.quote == 'account_rates':
            status = 'ready'
        elif self.quote in {'list_rates', 'rejected'}:
            status = 'account_rates_unverified'
        else:
            status = 'verification_pending'
        messages = {
            'service_unavailable': 'Capy’s connection service needs repair. Your account details are not needed right now.',
            'readiness_pending': 'Capy is checking account readiness.',
            'account_required': 'Connect your FedEx account to continue.',
            'account_rejected': 'FedEx did not accept the account details. You can correct them securely.',
            'verification_pending': 'Account verification is pending.',
            'origin_required': 'Account details accepted. Shipping origin is still needed.',
            'account_rates_unverified': 'Account-specific rates have not been verified.',
            'ready': 'Account and quote readiness verified.',
        }
        return {'status': status, 'message': messages[status]}
