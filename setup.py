from os import path
import sys
from codecs import open  # pylint:disable=redefined-builtin
from setuptools import setup
install_requires = ['construct', 'pillow', 'simplejson', 'pefile', 'pyscard', 'olefile', 'yara-python']
python_console_scripts = [
    'apc-b.py=didierstevenssuite.apc_b:Main',
    'byte-stats.py=didierstevenssuite.byte_stats:Main',
    'cipher-tool.py=didierstevenssuite.cipher_tool:Main',
    'cisco-calculate-ssh-fingerprint.py=didierstevenssuite.cisco_calculate_ssh_fingerprint:Main',
    'count.py=didierstevenssuite.count:Main',
    'cut-bytes.py=didierstevenssuite.cut_bytes:Main',
    'decode-vbe.py=didierstevenssuite.decode_vbe:Main',
    'defuzzer.py=didierstevenssuite.defuzzer:Main',
    'find-file-in-file.py=didierstevenssuite.find_file_in_file:Main',
    'generate-hashcat-toggle-rules.py=didierstevenssuite.generate_hashcat_toggle_rules:Main',
    'headtail.py=didierstevenssuite.headtail:Main',
    'hex-to-bin.py=didierstevenssuite.hex_to_bin:Main',
    'image-overlay.py=didierstevenssuite.image_overlay:Main',
    'jpegdump.py=didierstevenssuite.jpegdump:Main',
    'lookup-hosts.py=didierstevenssuite.lookup_hosts:Main',
    'naft-gfe.py=didierstevenssuite.naft_gfe:Main',
    'naft-icd.py=didierstevenssuite.naft_icd:Main',
    'naft-ii.py=didierstevenssuite.naft_ii:Main',
    'nmap-xml-script-output.py=didierstevenssuite.nmap_xml_script_output:Main',
    'nsrl.py=didierstevenssuite.nsrl:Main',
    'numbers-to-hex.py=didierstevenssuite.numbers_to_hex:Main',
    'numbers-to-string.py=didierstevenssuite.numbers_to_string:Main',
    'password-history-analysis.py=didierstevenssuite.password_history_analysis:Main',
    'pcap-rename.py=didierstevenssuite.pcap_rename:Main',
    'pdf-parser.py=didierstevenssuite.pdf_parser:Main',
    'pdfid.py=didierstevenssuite.pdfid:Main',
    'peid-userdb-to-yara-rules.py=didierstevenssuite.peid_userdb_to_yara_rules:Main',
    'python-per-line.py=didierstevenssuite.python_per_line:Main',
    're-search.py=didierstevenssuite.re_search:Main',
    'rtfdump.py=didierstevenssuite.rtfdump:Main',
    'sets.py=didierstevenssuite.sets:Main',
    'simple-shellcode-generator.py=didierstevenssuite.simple_shellcode_generator:Main',
    'split.py=didierstevenssuite.split:Main',
    'translate.py=didierstevenssuite.translate:Main',
    'wsrradial.py=didierstevenssuite.wsrradial:Main',
    'xor-kpa.py=didierstevenssuite.xor_kpa:Main',
]
python_scripts = ['bin/reextra.py', 'bin/decoder_add1.py', 'bin/decoder_ah.py', 'bin/decoder_chr.py', 'bin/decoder_rol1.py', 'bin/decoder_xor1.py', 'bin/make-pdf-helloworld.py', 'bin/naft_iipf.py', 'bin/naft_impf.py', 'bin/naft_pfef.py', 'bin/naft_uf.py', 'bin/plugin_biff.py', 'bin/plugin_dridex.py', 'bin/plugin_embeddedfile.py', 'bin/plugin_hifo.py', 'bin/plugin_http_heuristics.py', 'bin/plugin_jumplist.py', 'bin/plugin_linear.py', 'bin/plugin_nameobfuscation.py', 'bin/plugin_pcode_dumper.py', 'bin/plugin_str_sub.py', 'bin/plugin_stream_o.py', 'bin/plugin_stream_sample.py', 'bin/plugin_triage.py', 'bin/plugin_vba_summary.py']
python2_install_requires = ['poster', 'pyasn1', 'pyasn1-modules']
python2_console_scripts = [
    'MIFAREACR122.py=didierstevenssuite.MIFAREACR122:Main',
    'apc-channel.py=didierstevenssuite.apc_channel:Main',
    'apc-pr-log.py=didierstevenssuite.apc_pr_log:Main',
    'base64dump.py=didierstevenssuite.base64dump:Main',
    'disitool.py=didierstevenssuite.disitool:Main',
    'emldump.py=didierstevenssuite.emldump:Main',
    'file2vbscript.py=didierstevenssuite.file2vbscript:Main',
    'image-forensics-ela.py=didierstevenssuite.image_forensics_ela:Main',
    'lookup-ips.py=didierstevenssuite.lookup_ips:Main',
    'make-pdf-embedded.py=didierstevenssuite.make_pdf_embedded:Main',
    'make-pdf-javascript.py=didierstevenssuite.make_pdf_javascript:Main',
    'make-pdf-jbig2.py=didierstevenssuite.make_pdf_jbig2:Main',
    'oledump.py=didierstevenssuite.oledump:Main',
    'pecheck.py=didierstevenssuite.pecheck:Main',
    'shellcode2vba.py=didierstevenssuite.shellcode2vba:Main',
    'shellcode2vbscript.py=didierstevenssuite.shellcode2vbscript:Main',
    'virustotal-search.py=didierstevenssuite.virustotal_search:Main',
    'virustotal-submit.py=didierstevenssuite.virustotal_submit:Main',
    'vs.py=didierstevenssuite.vs:Main',
    'wsrtool.py=didierstevenssuite.wsrtool:Main',
    'zipdump.py=didierstevenssuite.zipdump:Main'
]
python2_scripts = ['bin/extractscripts.py']
python2_dependencies = ['bin/mPDF.py']
if sys.version_info[0:2] < (3, 0):
    python_console_scripts.extend(python2_console_scripts)
    python_scripts.extend(python2_scripts)
    python_scripts.extend(python2_dependencies)
    install_requires.extend(python2_install_requires)
here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'DESCRIPTION.rst'), encoding='utf-8') as f:
    long_description = f.read()
setup(
    name='didierstevenssuite',
    version='20171116a',
    description='Didier Stevens Suite',
    long_description=long_description,
    url='http://blog.didierstevens.com/didier-stevens-suite/',
    author='Didier Stevens',
    license='???',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    keywords='didier stevens pdf malware analysis',
    packages=['didierstevenssuite'],
    install_requires=install_requires,
    entry_points={
        'console_scripts': python_console_scripts
    },
    scripts=python_scripts
)
