#!/usr/bin/env python3
"""Compare the built native analyzer with pinned, CI-only pefile on generated PEs.

No downloaded executables, execution of fixtures, or runtime crate dependencies.
Usage: python3 scripts/check_pe_differential.py --binary target/release/rea-offline
Install development requirements from scripts/requirements-pe-tests.txt first.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile


def fixture(bits=64, ordinal=False, certificate=False, overlay=False, writable=False, imports=True):
    """Minimal static-only image: one section, optional named/ordinal imports.

    Not an executable test program: no code is supplied at the entry point.
    All imports, headers and certificate placeholders are synthetic.
    """
    data = bytearray(0x600)
    def put(offset, fmt, value):
        struct.pack_into('<' + fmt, data, offset, value)
    data[:2] = b'MZ'
    put(0x3c, 'I', 0x80)
    data[0x80:0x84] = b'PE\0\0'
    opt = 0x98
    opt_size = 240 if bits == 64 else 224
    put(0x84, 'H', 0x8664 if bits == 64 else 0x14c)
    put(0x86, 'H', 1)
    put(0x88, 'I', 0x65000000)
    put(0x94, 'H', opt_size)
    put(0x96, 'H', 0x22 if bits == 64 else 0x102)
    put(opt, 'H', 0x20b if bits == 64 else 0x10b)
    put(opt + 16, 'I', 0x1000)
    put(opt + (24 if bits == 64 else 28), 'Q' if bits == 64 else 'I', 0x400000)
    put(opt + 32, 'I', 0x1000)
    put(opt + 36, 'I', 0x200)
    put(opt + 56, 'I', 0x2000)
    put(opt + 60, 'I', 0x200)
    put(opt + 68, 'H', 3)
    put(opt + 70, 'H', 0x4160)
    directory = opt + (112 if bits == 64 else 96)
    put(directory - 4, 'I', 16)
    section = opt + opt_size
    data[section:section + 8] = b'.text\0\0\0'
    for delta, value in [(8, 0x400), (12, 0x1000), (16, 0x400), (20, 0x200), (36, 0xe0000020 if writable else 0x60000020)]:
        put(section + delta, 'I', value)
    if imports:
        put(directory + 8, 'I', 0x1100)
        put(directory + 12, 'I', 40)
        put(0x300, 'I', 0x1140)
        put(0x30c, 'I', 0x1180)
        put(0x310, 'I', 0x1140)
        data[0x380:0x38d] = b'KERNEL32.dll\0'
        name = b'CreateRemoteThread\0'
        data[0x392:0x392 + len(name)] = name
        put(0x340, 'Q' if bits == 64 else 'I', 0x1190)
        if ordinal:
            put(0x348 if bits == 64 else 0x344, 'Q' if bits == 64 else 'I', (1 << (bits - 1)) | 42)
    if overlay:
        data.extend(b'PRE-CERTIFICATE-PAYLOAD'.ljust(32, b'!'))
    if certificate:
        put(directory + 32, 'I', len(data))
        put(directory + 36, 'I', 8)
        data.extend(struct.pack('<IHH', 8, 0x200, 2))
    if overlay:
        data.extend(b'POST-CERTIFICATE-PAYLOAD'.ljust(64, b'!'))
    return bytes(data)


def compare(native, oracle, data, label):
    """Fail with a field-level diagnostic rather than comparing opaque JSON."""
    def equal(field, actual, expected):
        if actual != expected:
            raise AssertionError('{}: {}: native={!r}, pefile={!r}'.format(label, field, actual, expected))
    pe = native['pe']
    equal('size', native['size'], len(data))
    equal('sha256', native['sha256'], hashlib.sha256(data).hexdigest())
    equal('md5', native['md5'], hashlib.md5(data).hexdigest())
    equal('64-bit', pe['is_64bit'], oracle.OPTIONAL_HEADER.Magic == 0x20b)
    equal('machine', pe['machine'], {0x14c: 'x86', 0x8664: 'x86-64'}[oracle.FILE_HEADER.Machine])
    equal('timestamp', pe['timestamp'], oracle.FILE_HEADER.TimeDateStamp)
    equal('entry RVA', pe['entry_point_rva'], oracle.OPTIONAL_HEADER.AddressOfEntryPoint)
    equal('section count', len(pe['section_details']), len(oracle.sections))
    for index, (section, reference) in enumerate(zip(pe['section_details'], oracle.sections)):
        for key, value in [('name', reference.Name.rstrip(b'\0').decode('ascii')), ('raw_offset', reference.PointerToRawData), ('raw_size', reference.SizeOfRawData), ('virtual_address', reference.VirtualAddress), ('virtual_size', reference.Misc_VirtualSize), ('executable', bool(reference.Characteristics & 0x20000000)), ('writable', bool(reference.Characteristics & 0x80000000))]:
            equal('section {} {}'.format(index, key), section[key], value)
        if abs(section['entropy'] - reference.get_entropy()) > 0.0011:
            raise AssertionError('{}: section entropy differs'.format(label))
    descriptors = getattr(oracle, 'DIRECTORY_ENTRY_IMPORT', [])
    equal('libraries', pe['imports'], [d.dll.decode('ascii') for d in descriptors])
    functions = [d.dll.decode('ascii') + '!' + (entry.name.decode('ascii') if entry.name else '#' + str(entry.ordinal)) for d in descriptors for entry in d.imports]
    equal('functions', pe['imported_functions'], functions)
    equal('imphash', native['imphash'], oracle.get_imphash() or None)
    flags = oracle.OPTIONAL_HEADER.DllCharacteristics
    for key, bit in [('aslr_dynamic_base', 0x40), ('nx_compat', 0x100), ('guard_cf', 0x4000), ('no_seh', 0x400), ('high_entropy_va', 0x20)]:
        equal(key, pe['mitigations'][key], bool(flags & bit))
    security = oracle.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    cert = {'offset': security.VirtualAddress, 'size': security.Size} if security.VirtualAddress else None
    equal('certificate presence', pe['signed'], cert is not None)
    equal('certificate range', pe['certificate_range'], cert)
    start = max([oracle.OPTIONAL_HEADER.SizeOfHeaders] + [s.PointerToRawData + s.SizeOfRawData for s in oracle.sections])
    ranges = []
    if cert:
        if start < cert['offset']:
            ranges.append({'offset': start, 'size': cert['offset'] - start})
        start = cert['offset'] + cert['size']
    if start < len(data):
        ranges.append({'offset': start, 'size': len(data) - start})
    equal('overlay ranges', pe['overlay_ranges'], ranges)
    equal('overlay bytes', pe['overlay_size'], sum(r['size'] for r in ranges))


def main():
    import pefile  # Deliberately not a runtime or stdlib-unit-test dependency.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    cases = [dict(), dict(ordinal=True), dict(certificate=True), dict(certificate=True, overlay=True), dict(overlay=True, writable=True), dict(imports=False)]
    with tempfile.TemporaryDirectory(prefix='rea-pe-differential-') as temporary:
        root = Path(temporary)
        env = dict(os.environ, PATH='', REA_PATH='')  # Disable optional external discovery.
        for bits in (32, 64):
            for index, options in enumerate(cases):
                label = 'PE{} case {}'.format(bits, index)
                data = fixture(bits=bits, **options)
                target, output = root / 'fixture.exe', root / 'report.json'
                target.write_bytes(data)
                result = subprocess.run([str(binary), 'scan', str(target), '--output', str(output), '--quiet'], env=env, capture_output=True, timeout=30)
                if result.returncode:
                    raise RuntimeError('{}: scan failed: {!r}'.format(label, result.stderr))
                report = json.loads(output.read_text(encoding='utf-8'))
                compare(report['report']['files'][0], pefile.PE(data=data), data, label)
                print('PASS ' + label)
    print('12 generated fixtures match pefile; no fixture was executed.')


if __name__ == '__main__':
    main()
