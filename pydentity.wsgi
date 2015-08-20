import sys
from os.path import dirname, join

sys.path.insert(0, dirname(__file__))

activate_this = join(dirname(__file__), "venv", "bin", "activate_this.py")
execfile(activate_this, dict(__file__=activate_this))

print sys.path
from pydentity import app as application
application.debug=True