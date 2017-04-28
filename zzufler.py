"""
ZZufler trivial HTTP python fuzzer based on zzuf.
MIT License
Copyright (c) 2016 Daniele Linguaglossa <danielelinguaglossa@gmail.com>
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sys
import random
import subprocess
from burp import ITab
from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from javax.swing import JLabel, JTextField, JOptionPane, JTabbedPane, JPanel, JButton
from java.awt import GridBagLayout, GridBagConstraints

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, ITab):
    name = "ZZufler"
    args = []
    binary = ""
    _jTabbedPane = JTabbedPane()
    _jPanel = JPanel()
    _jAboutPanel = JPanel()
    _jPanelConstraints = GridBagConstraints()
    aboutText = "<h1>How-to</h1><br>" \
                "<pre>In order to use ZZufler you MUST install zzuf from source using: <br>" \
                "<b>git clone https://github.com/samhocevar/zzuf.git && make && sudo make install</b><br>" \
                "Once done zzuf should be in your PATH so try:<br>" \
                "<b>echo 'fuzzme!' | zuff -r 0.01 -s 1</b><br>" \
                "If you get a different result from the original 'fuzzme' than you're ready to go!</pre><br><br>" \
                "<h1>About me</h1><br>" \
                "I'm a security expert working @ Consulthink S.p.A. passionate about fuzzing and exploitation!<br>" \
                "<h1>About ZZufler</h1><br>" \
                "ZZufler is still a 'work in progress' tool it will be upgraded every time is possible so stay tuned!<br><br>" \
                "<center><h2>Happy fuzzing!</h2></center>"

    def registerExtenderCallbacks(self, callbacks):
        find_bin = subprocess.Popen(["/usr/bin/which", "zzuf"],stdout=subprocess.PIPE)
        find_bin.wait()
        self.binary=find_bin.stdout.read().replace("\n", "").replace("\r", "")
        if not self.binary:
            sys.stderr.write("Unable to find zzuf in path! Please symlink zzuf to /usr/local/bin/zzuf ")
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.name)
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        callbacks.addSuiteTab(self)
        self.initPanelConfig()
        self._jTabbedPane.addTab("Configuration", self._jPanel)
        self._jTabbedPane.addTab("About", self._jAboutPanel)
        return

    def getUiComponent(self):
        return self._jTabbedPane

    def getTabCaption(self):
        return "ZZufler"

    def initPanelConfig(self):
        self._jPanel.setBounds(0, 0, 1000, 1000)
        self._jPanel.setLayout(GridBagLayout())

        self._jAboutPanel.setBounds(0, 0, 1000, 1000)
        self._jAboutPanel.setLayout(GridBagLayout())

        self._jLabelSwitches = JLabel("zzuf switches: ")
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 0
        self._jPanel.add(self._jLabelSwitches, self._jPanelConstraints)

        self._jTextFieldSwitches = JTextField("", 15)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 0
        self._jPanel.add(self._jTextFieldSwitches, self._jPanelConstraints)

        self._jButtonSetCommandLine = JButton('Set Configuration', actionPerformed=self.setCommandLine)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 5
        self._jPanelConstraints.gridwidth = 2
        self._jPanel.add(self._jButtonSetCommandLine, self._jPanelConstraints)

        self._jLabelAbout = JLabel("<html><body>%s</body></html>" % self.aboutText)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 0
        self._jAboutPanel.add(self._jLabelAbout, self._jPanelConstraints)

    def setCommandLine(self, event=None):
        switches = self._jTextFieldSwitches.getText()
        self.args = switches.split(" ")
        JOptionPane.showMessageDialog(None, "Command line configured!")

    def getGeneratorName(self):
        return "ZZufler"

    def createNewInstance(self, attack):
        return HTTPFuzzer(self, attack, self.binary, self.args)


class HTTPFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack, zzuf, args):
        self._args = args
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        if zzuf:
            self.zzuf = zzuf
        else:
            self.zzuf = "/usr/local/bin/zzuf"
        return

    def hasMorePayloads(self):
        return True

    def getNextPayload(self, current_payload):
        payload = "".join(chr(x) for x in current_payload)
        payload = self.fuzz(payload)
        return payload

    def reset(self):
        return

    def fuzz(self, original_payload):
        p0 = subprocess.Popen(["/bin/echo", "-n", original_payload], stdout=subprocess.PIPE)
        p1 = subprocess.Popen([self.zzuf ,"-r", str(random.uniform(0.004, 0.05)), "-P" ,
                               "\\r\\n", "-R", "\\x00-\\x1f\\x7f-\\xff"], stdin=p0.stdout, stdout=subprocess.PIPE)
        output = p1.stdout.read()
        del p0,p1
        return output
