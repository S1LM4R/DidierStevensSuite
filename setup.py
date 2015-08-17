"""A setuptools based setup module.
See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'DESCRIPTION.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='didier_stevens_suite',

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version='1.0.0',

    description='Didier Stevens Suite',
    long_description=long_description,

    # The project's main homepage.
    url='http://blog.didierstevens.com/didier-stevens-suite/',

    # Author details
    author='Didier Stevens',
    # author_email='pypa-dev@googlegroups.com',

    # Choose your license
    license='???',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        #'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],

    # What does your project relate to?
    keywords='didier stevens pdf malware analysis',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=['didier_stevens_suite'],

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['peppercorn'],

    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    # extras_require={
    #    'dev': ['check-manifest'],
    #    'test': ['coverage'],
    #},

    # If there are data files included in your packages that need to be
    # installed, specify them here.  If using Python 2.6 or less, then these
    # have to be included in MANIFEST.in as well.
    # package_data={
    #    'sample': ['package_data.dat'],
    #},

    # Although 'package_data' is the preferred approach, in some case you may
    # need to place data files outside of your packages. See:
    # http://docs.python.org/3.4/distutils/setupscript.html#installing-additional-files # noqa
    # In this case, 'data_file' will be installed into '<sys.prefix>/my_data'
    #data_files=[('my_data', ['data/data_file'])],

    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    entry_points={
        'console_scripts': [
'apc-b.py=didier_stevens_suite:apc_b.Main',
'apc-channel.py=didier_stevens_suite:apc_channel.Main',
'apc-pr-log.py=didier_stevens_suite:apc_pr_log.Main',
'base64dump.py=didier_stevens_suite:base64dump.Main',
'cisco-calculate-ssh-fingerprint.py=didier_stevens_suite:cisco_calculate_ssh_fingerprint.Main',
'count.py=didier_stevens_suite:count.Main',
'decoder_add1.py=didier_stevens_suite:decoder_add1.Main',
'decoder_ah.py=didier_stevens_suite:decoder_ah.Main',
'decoder_chr.py=didier_stevens_suite:decoder_chr.Main',
'decoder_rol1.py=didier_stevens_suite:decoder_rol1.Main',
'decoder_xor1.py=didier_stevens_suite:decoder_xor1.Main',
'defuzzer.py=didier_stevens_suite:defuzzer.Main',
'disitool.py=didier_stevens_suite:disitool.Main',
'emldump.py=didier_stevens_suite:emldump.Main',
'extractscripts.py=didier_stevens_suite:extractscripts.Main',
'file2vbscript.py=didier_stevens_suite:file2vbscript.Main',
'find-file-in-file.py=didier_stevens_suite:find_file_in_file.Main',
'image-forensics-ela.py=didier_stevens_suite:image_forensics_ela.Main',
'image-overlay.py=didier_stevens_suite:image_overlay.Main',
'lookup-hosts.py=didier_stevens_suite:lookup_hosts.Main',
'lookup-ips.py=didier_stevens_suite:lookup_ips.Main',
'make-pdf-embedded.py=didier_stevens_suite:make_pdf_embedded.Main',
'make-pdf-helloworld.py=didier_stevens_suite:make_pdf_helloworld.Main',
'make-pdf-javascript.py=didier_stevens_suite:make_pdf_javascript.Main',
'make-pdf-jbig2.py=didier_stevens_suite:make_pdf_jbig2.Main',
'MIFAREACR122.py=didier_stevens_suite:MIFAREACR122.Main',
'mPDF.py=didier_stevens_suite:mPDF.Main',
'naft-gfe.py=didier_stevens_suite:naft_gfe.Main',
'naft-icd.py=didier_stevens_suite:naft_icd.Main',
'naft_iipf.py=didier_stevens_suite:naft_iipf.Main',
'naft-ii.py=didier_stevens_suite:naft_ii.Main',
'naft_impf.py=didier_stevens_suite:naft_impf.Main',
'naft_pfef.py=didier_stevens_suite:naft_pfef.Main',
'naft_uf.py=didier_stevens_suite:naft_uf.Main',
'nmap-xml-script-output.py=didier_stevens_suite:nmap_xml_script_output.Main',
'oledump.py=didier_stevens_suite:oledump.Main',
'pcap-rename.py=didier_stevens_suite:pcap_rename.Main',
'pdfid.py=didier_stevens_suite:pdfid.Main',
'pdf-parser.py=didier_stevens_suite:pdf_parser.Main',
'pecheck.py=didier_stevens_suite:pecheck.Main',
'peid-userdb-to-yara-rules.py=didier_stevens_suite:peid_userdb_to_yara_rules.Main',
'plugin_biff.py=didier_stevens_suite:plugin_biff.Main',
'plugin_dridex.py=didier_stevens_suite:plugin_dridex.Main',
'plugin_embeddedfile.py=didier_stevens_suite:plugin_embeddedfile.Main',
'plugin_http_heuristics.py=didier_stevens_suite:plugin_http_heuristics.Main',
'plugin_jumplist.py=didier_stevens_suite:plugin_jumplist.Main',
'plugin_nameobfuscation.py=didier_stevens_suite:plugin_nameobfuscation.Main',
'plugin_triage.py=didier_stevens_suite:plugin_triage.Main',
'plugin_vba_summary.py=didier_stevens_suite:plugin_vba_summary.Main',
'reextra.py=didier_stevens_suite:reextra.Main',
're-search.py=didier_stevens_suite:re_search.Main',
'shellcode2vba.py=didier_stevens_suite:shellcode2vba.Main',
'shellcode2vbscript.py=didier_stevens_suite:shellcode2vbscript.Main',
'simple-shellcode-generator.py=didier_stevens_suite:simple_shellcode_generator.Main',
'split.py=didier_stevens_suite:split.Main',
'translate.py=didier_stevens_suite:translate.Main',
'virustotal-search.py=didier_stevens_suite:virustotal_search.Main',
'virustotal-submit.py=didier_stevens_suite:virustotal_submit.Main',
'vs.py=didier_stevens_suite:vs.Main',
'wsrradial.py=didier_stevens_suite:wsrradial.Main',
'wsrtool.py=didier_stevens_suite:wsrtool.Main',
'zipdump.py=didier_stevens_suite:zipdump.Main'],
    },
)
