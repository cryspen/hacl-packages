#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import subprocess

def build_ocaml():
    '''Build the OCaml bindings.
    '''
    make_cmd = ['make', '-C', 'ocaml', 'setup', '-j']
    subprocess.run(make_cmd, check=True)
    make_cmd = ['make', '-C', 'ocaml', 'ocamlevercrypt.cmxa', '-j']
    subprocess.run(make_cmd, check=True)
    make_cmd = ['make', '-C', 'ocaml', '-j']
    subprocess.run(make_cmd, check=True)


def clean_ocaml():
    '''Clean the OCaml build.
    '''
    make_cmd = ['make', '-C', 'ocaml', 'clean']
    subprocess.run(make_cmd, check=True)
