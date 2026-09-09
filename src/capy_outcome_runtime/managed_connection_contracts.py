"""Finite, credential-free authoring metadata for supported managed contracts."""
from __future__ import annotations

import copy

from .developer_link import LinkError


def obj(properties, required=None):
    return {'type': 'object', 'additionalProperties': False, 'properties': properties,
            'required': list(properties) if required is None else required}


def plain(maximum):
    return {'type': 'string', 'minLength': 1, 'maxLength': maximum,
            'description': 'Nonempty text without surrounding whitespace or control characters.'}


MONEY = obj({'amount': {'type': 'number', 'minimum': 0, 'maximum': 1000000000},
             'currency': {'type': 'string', 'pattern': '^[A-Z]{3}$'}})
SUMMARY = obj({'country_code': {'type': 'string'}, 'postal_code': {'type': 'string'}})
FEDEX_REQUEST = obj({
    'destination': obj({'city': plain(128), 'country_code': {'type': 'string', 'pattern': '^[A-Z]{2}$'},
                        'postal_code': plain(32), 'residential': {'type': 'boolean'}, 'state_or_province': plain(32)}),
    'ship_date': {'type': 'string', 'format': 'date', 'pattern': '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'},
    'packages': {'type': 'array', 'minItems': 1, 'maxItems': 40, 'items': obj({
        'package_id': plain(100),
        'weight_kg': {'oneOf': [{'type': 'number', 'minimum': 0.001, 'maximum': 10000},
                               {'type': 'string', 'maxLength': 64, 'pattern': r'^[+-]?(?:\d{1,32}(?:\.\d{0,16})?|\.\d{1,16})(?:[eE][+-]?\d{1,3})?$'}],
                      'description': 'Decimal weight in kilograms, inclusive 0.001 to 10000, including numeric strings; at most 16 fractional decimal digits and 64 characters.'},
        'length_cm': {'type': 'integer', 'minimum': 1, 'maximum': 9999},
        'width_cm': {'type': 'integer', 'minimum': 1, 'maximum': 9999},
        'height_cm': {'type': 'integer', 'minimum': 1, 'maximum': 9999},
        'quantity': {'type': 'integer', 'minimum': 1, 'maximum': 999}})},
    'include_list_rates': {'type': 'boolean'}, 'return_transit_times': {'type': 'boolean'},
})
RATE = obj({'service_type': {'type': 'string'}, 'service_name': {'type': 'string'},
            'account_total': MONEY, 'list_total': MONEY,
            'surcharges': {'type': 'array', 'items': obj({'type': {'type': 'string'}, **MONEY['properties']})},
            'transit_days': {'type': 'string'}, 'delivery_date': {'type': 'string'},
            'warnings': {'type': 'array', 'items': {'type': 'string'}}},
           ['service_type', 'surcharges', 'warnings'])
RATE['anyOf'] = [{'required': ['account_total']}, {'required': ['list_total']}]
FEDEX_RESULT = obj({'destination_summary': SUMMARY, 'environment': {'type': 'string', 'enum': ['sandbox', 'production']},
                    'origin_summary': SUMMARY, 'provider_transaction_id': {'type': 'string'},
                    'quoted_at': {'type': 'string'}, 'rates': {'type': 'array', 'minItems': 1, 'items': RATE}})
FEDEX = {
    'contract': 'fedex.rates/v1', 'name': 'FedEx shipping rates', 'operation': 'quote',
    'request_schema': FEDEX_REQUEST, 'result_schema': FEDEX_RESULT,
    'credential': 'managed_by_capy', 'binding': 'team_configuration', 'availability': 'not_checked',
    'notes': [
        'Read-only rate quote. The application calls the managed connection; it never supplies provider credentials or account identifiers.',
        'The destination city, state_or_province, postal_code, country_code and residential flag are all required. Collect missing values from the user; do not invent them.',
        'Collect an actual valid calendar ship_date in YYYY-MM-DD form. The example is synthetic, not a default shipment date.',
        'All package fields are required. The sum of package quantities must be at most 40.',
        'Numeric strings for weight must also meet the stated numeric bounds. Boolean values are not weights or integer dimensions.',
        'Results have one or both account_total and list_total; optional service_name, transit_days and delivery_date may be absent. transit_days is provider text, not necessarily a number.',
        'Rates are sorted by account total when present, otherwise list total. All returned monetary currencies must agree.',
        'Availability and credentials have not been inspected. The team configuration binds an approved managed connection before invocation.',
    ],
    'examples': [{'request': {'destination': {'city': 'Austin', 'country_code': 'US', 'postal_code': '78701',
                                            'residential': False, 'state_or_province': 'TX'},
                               'ship_date': '2030-01-15', 'packages': [{'package_id': 'parcel-1', 'weight_kg': 2,
                                    'length_cm': 20, 'width_cm': 15, 'height_cm': 10, 'quantity': 1}],
                               'include_list_rates': True, 'return_transit_times': True},
                  'result': {'destination_summary': {'country_code': 'US', 'postal_code': '78701'},
                             'environment': 'sandbox', 'origin_summary': {'country_code': 'KR', 'postal_code': '00000'},
                             'provider_transaction_id': 'synthetic-example', 'quoted_at': '2030-01-01T00:00:00Z',
                             'rates': [{'service_type': 'INTERNATIONAL_PRIORITY', 'account_total': {'amount': 50, 'currency': 'USD'},
                                        'surcharges': [], 'warnings': []}]}}],
}


COMMODITY = obj({
    'description': plain(450),
    'quantity': {'type': 'integer', 'minimum': 1, 'maximum': 1000000},
    'country_of_manufacture': {'type': 'string', 'pattern': '^[A-Z]{2}$'},
    'customs_value': obj({'amount': {'oneOf': [
        {'type': 'number', 'minimum': 0.000001, 'maximum': 1000000000},
        {'type': 'string', 'maxLength': 64, 'pattern': r'^[+-]?(?:\d{1,32}(?:\.\d{0,16})?|\.\d{1,16})(?:[eE][+-]?\d{1,3})?$'}]},
        'currency': {'type': 'string', 'pattern': '^[A-Z]{3}$'}}),
})
FEDEX_V2=copy.deepcopy(FEDEX)
FEDEX_V2.update(contract='fedex.rates/v2',name='FedEx shipping rates with customs details')
FEDEX_V2['request_schema']['properties']['commodities']={
    'type':'array','minItems':1,'maxItems':40,'items':COMMODITY}
FEDEX_V2['request_schema']['required'].append('commodities')
FEDEX_V2['notes'] += [
    'Collect description, unit quantity, manufacturing country, total customs value and currency for every commodity group. Values are shipment totals for each commodity, not per-unit prices.',
    'All commodity currencies must agree. Positive customs values and their sum must be at most 1000000000; numeric strings have the same bounds. Do not invent goods, customs values or tariff codes.',
    'Quantity is the number of product units (PCS), not the number of boxes. No duties/tax estimate, customs filing or shipping purchase is promised.',
]
FEDEX_V2['examples'][0]['request']['commodities']=[{
    'description':'Synthetic test serum','quantity':10,'country_of_manufacture':'KR',
    'customs_value':{'amount':100,'currency':'USD'}}]


def contracts(contract=None):
    supported=[FEDEX,FEDEX_V2]
    if contract is not None:
        supported=[item for item in supported if item['contract']==contract]
        if not supported:raise LinkError('CONNECTION_CONTRACT_UNSUPPORTED',404)
    return {'schema':'capy.managed-connection-contracts/v0','contracts':copy.deepcopy(supported)}
