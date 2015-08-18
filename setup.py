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
    name='didierstevenssuite',

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
    packages=['didierstevenssuite'],

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['pillow', 'poster', 'simplejson', 'pefile', 'pyscard'],

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
'apc-b.py=didierstevenssuite.apc_b:Main',
'apc-channel.py=didierstevenssuite.apc_channel:Main',
'apc-pr-log.py=didierstevenssuite.apc_pr_log:Main',
'base64dump.py=didierstevenssuite.base64dump:Main',
'cisco-calculate-ssh-fingerprint.py=didierstevenssuite.cisco_calculate_ssh_fingerprint:Main',
'count.py=didierstevenssuite.count:Main',
'defuzzer.py=didierstevenssuite.defuzzer:Main',
'disitool.py=didierstevenssuite.disitool:Main',
'emldump.py=didierstevenssuite.emldump:Main',
'extractscripts.py=didierstevenssuite.extractscripts:Main',
'file2vbscript.py=didierstevenssuite.file2vbscript:Main',
'find-file-in-file.py=didierstevenssuite.find_file_in_file:Main',
'image-forensics-ela.py=didierstevenssuite.image_forensics_ela:Main',
'image-overlay.py=didierstevenssuite.image_overlay:Main',
'lookup-hosts.py=didierstevenssuite.lookup_hosts:Main',
'lookup-ips.py=didierstevenssuite.lookup_ips:Main',
'make-pdf-embedded.py=didierstevenssuite.make_pdf_embedded:Main',
'make-pdf-helloworld.py=didierstevenssuite.make_pdf_helloworld:Main',
'make-pdf-javascript.py=didierstevenssuite.make_pdf_javascript:Main',
'make-pdf-jbig2.py=didierstevenssuite.make_pdf_jbig2:Main',
'MIFAREACR122.py=didierstevenssuite.MIFAREACR122:Main',
'naft-gfe.py=didierstevenssuite.naft_gfe:Main',
'naft-icd.py=didierstevenssuite.naft_icd:Main',
'naft_iipf.py=didierstevenssuite.naft_iipf:Main',
'naft-ii.py=didierstevenssuite.naft_ii:Main',
'naft_uf.py=didierstevenssuite.naft_uf:Main',
'nmap-xml-script-output.py=didierstevenssuite.nmap_xml_script_output:Main',
'oledump.py=didierstevenssuite.oledump:Main',
'pcap-rename.py=didierstevenssuite.pcap_rename:Main',
'pdfid.py=didierstevenssuite.pdfid:Main',
'pdf-parser.py=didierstevenssuite.pdf_parser:Main',
'pecheck.py=didierstevenssuite.pecheck:Main',
'peid-userdb-to-yara-rules.py=didierstevenssuite.peid_userdb_to_yara_rules:Main',
're-search.py=didierstevenssuite.re_search:Main',
'shellcode2vba.py=didierstevenssuite.shellcode2vba:Main',
'shellcode2vbscript.py=didierstevenssuite.shellcode2vbscript:Main',
'simple-shellcode-generator.py=didierstevenssuite.simple_shellcode_generator:Main',
'split.py=didierstevenssuite.split:Main',
'translate.py=didierstevenssuite.translate:Main',
'virustotal-search.py=didierstevenssuite.virustotal_search:Main',
'virustotal-submit.py=didierstevenssuite.virustotal_submit:Main',
'vs.py=didierstevenssuite.vs:Main',
'wsrradial.py=didierstevenssuite.wsrradial:Main',
'wsrtool.py=didierstevenssuite.wsrtool:Main',
'zipdump.py=didierstevenssuite.zipdump:Main'],
    },
)
