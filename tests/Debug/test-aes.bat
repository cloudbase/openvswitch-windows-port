@echo off
test-aes128.exe 00010203050607080a0b0c0d0f101112 506812a45f08c889b97f5980038b8359 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == d8f532538289ef7d06b506a4fd5be9c9 echo BAD1

test-aes128.exe 95A8EE8E89979B9EFDCBC6EB9797528D 4ec137a426dabf8aa0beb8bc0c2b89d6 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == d9b65d1232ba0199cdbd487b2a1fd646 echo BAD2

test-aes128.exe 10a58869d74be5a374cf867cfb473859 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 6d251e6944b051e04eaa6fb4dbf78465 echo BAD3

test-aes128.exe caea65cdbb75e9169ecd22ebe6e54675 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 6e29201190152df4ee058139def610bb echo BAD4

test-aes128.exe a2e2fa9baf7d20822ca9f0542f764a41 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == c3b44b95d9d2f25670eee9a0de099fa3 echo BAD5

test-aes128.exe b6364ac4e1de1e285eaf144a2415f7a0 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 5d9b05578fc944b3cf1ccf0e746cd581 echo BAD6

test-aes128.exe 64cf9c7abc50b888af65f49d521944b2 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == f7efc89d5dba578104016ce5ad659c05 echo BAD7

test-aes128.exe 47d6742eefcc0465dc96355e851b64d9 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 0306194f666d183624aa230a8b264ae7 echo BAD8

test-aes128.exe 3eb39790678c56bee34bbcdeccf6cdb5 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 858075d536d79ccee571f7d7204b1f67 echo BAD9

test-aes128.exe 64110a924f0743d500ccadae72c13427 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 35870c6a57e9e92314bcb8087cde72ce echo BAD10

test-aes128.exe f530357968578480b398a3c251cd1093 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == f5df39990fc688f1b07224cc03e86cea echo BAD11

test-aes128.exe da84367f325d42d601b4326964802e8e 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == bba071bcb470f8f6586e5d3add18bc66 echo BAD12

test-aes128.exe e37b1c6aa2846f6fdb413f238b089f23 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 43c9f7e62f5d288bb27aa40ef8fe1ea8 echo BAD13

test-aes128.exe 6c002b682483e0cabcc731c253be5674 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 3580d19cff44f1014a7c966a69059de5 echo BAD14

test-aes128.exe b69418a85332240dc82492353956ae0c 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == a303d940ded8f0baff6f75414cac5243 echo BAD15

test-aes128.exe 71b5c08a1993e1362e4d0ce9b22b78d5 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == c2dabd117f8a3ecabfbb11d12194d9d0 echo BAD16

test-aes128.exe e234cdca2606b81f29408d5f6da21206 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == fff60a4740086b3b9c56195b98d91a7b echo BAD17

test-aes128.exe 13237c49074a3da078dc1d828bb78c6f 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 8146a08e2357f0caa30ca8c94d1a0544 echo BAD18

test-aes128.exe 3071a2a48fe6cbd04f1a129098e308f8 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 4b98e06d356deb07ebb824e5713f7be3 echo BAD19

test-aes128.exe 90f42ec0f68385f2ffc5dfc03a654dce 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == 7a20a53d460fc9ce0423a7a0764c6cf2 echo BAD20

test-aes128.exe febd9a24d8b65c1c787d50a4ed3619a9 00000000000000000000000000000000 > temp.txt
set /p VAR=<temp.txt
if not %VAR% == f4a70d8af877f9b02b4c40df57d45b17 echo BAD21
