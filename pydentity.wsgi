import sys
from os.path import dirname, join

sys.path.insert(0, dirname(__file__))

print(sys.path)
from pydentity import app as application
application.debug=True
