#!/usr/bin/python3 -su

## Copyright (C) 2015 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import sys
import signal

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QMenu, QAction
from PyQt5.QtCore import *

import subprocess
import json
import os
import re
import glob

anon_connection_wizard_installed = os.path.exists('/usr/bin/anon-connection-wizard')
if anon_connection_wizard_installed:
    from anon_connection_wizard import tor_status


class AnonVmWatcher(QThread):
    signal = pyqtSignal(str)

    def __init__(self, main, domains):
        super(AnonVmWatcher, self).__init__(main)
        self.domains = domains

    def watch_anon_vms(self):
        '''
        Set a timeout in qrexec-client-vm command.
        When a vm is killed, qrexec-client-vm is not responding from any vm
        for a period of time. The minimum timeout seems to be 5 seconds on
        my machine.
        Set a safe 8 seconds to prevent removing running vms.

        The killed or crashed vm is restarted by the qrexec-client-vm command.
        '''
        #print("watch_anon_vms:")
        seconds = 8
        for domain in self.domains[1:]: ## Do not check sys-whonix
            try:
                command = ['qrexec-client-vm', domain, 'whonix.SdwdateStatus']
                subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=seconds)
                #print("ok: " + domain)
            except:
                #print("emit: " + domain)
                self.signal.emit(domain)

    def run(self):
        watch = self.watch_anon_vms()


class SdwdateTrayIcon(QtWidgets.QSystemTrayIcon):
    def __init__(self, parent=None):
        QtWidgets.QSystemTrayIcon.__init__(self, parent)

        self.title = 'Time Synchronisation Monitor'

        try:
            command = ['qubesdb-read', '/name']
            output = subprocess.check_output(command, timeout=5)
        except subprocess.TimeoutExpired:
            print("SdwdateTrayIcon __init__: ERROR: Command 'qubesdb-read /name' timed out.")
            output = b''
        except Exception as e:
            print(f"Error executing command: {e}")
            output = b''

        if output:
            self.name = output.decode().strip()
        else:
            self.name = "qubesdb-read-slash-name-timeout"

        self.status_path =          '/run/sdwdate/status'
        self.anon_status_path =     '/run/sdwdate-gui/anon-status'
        ## /run/sdwdate-gui/anon-status content example:
        ## anon-whonix
        ## /run/sdwdate-gui/anon-status content example:
        ## anon-whonix shutdown
        self.show_message_path =    '/usr/libexec/sdwdate-gui/show_message'
        self.tor_path =             '/run/tor'
        self.tor_running_path =     '/run/tor/tor.pid'
        self.torrc_path =           '/usr/local/etc/torrc.d/'

        self.popup_process = None

        self.clicked_once = False
        self.pos_x = 0
        self.pos_y = 0

        self.domain_list = []
        self.domain_status_list = []
        self.domain_icon_list = []
        self.domain_message_list = []
        self.current_vm = ''

        self.icon_path = '/usr/share/sdwdate-gui/icons/'

        self.tor_icon = [self.icon_path + 'tor-ok.png',
                         self.icon_path + 'tor-error.png',
                         self.icon_path + 'tor-error.png',
                         self.icon_path + 'tor-warning.png']

        self.tor_status_list = ['running',
                                'stopped',
                                'disabled',
                                'disabled-running']

        self.tor_status = 'stopped'
        self.tor_message =  ''
        self.is_tor_message = False

        self.icon = [self.icon_path + 'sdwdate-success.png',
                     self.icon_path + 'sdwdate-wait.png',
                     self.icon_path + 'sdwdate-stopped.png']

        self.status = ['success', 'busy', 'error']

        self.domain_list.append(self.name)
        self.domain_status_list.append('busy')
        self.domain_icon_list.append(self.icon[self.status.index('busy')])
        self.domain_message_list.append('Waiting for first sdwdate status...')

        self.setIcon(QtGui.QIcon(self.icon[self.status.index('busy')]))

        self.setToolTip('Time Synchronisation Monitor \n Click for menu.')

        if anon_connection_wizard_installed:
            self.tor_watcher = QFileSystemWatcher([self.tor_path, self.torrc_path])
            self.tor_watcher.directoryChanged.connect(self.tor_status_changed)
        else:
            self.tor_status = 'running'

        self.sdwdate_watcher = QFileSystemWatcher([self.status_path])
        self.sdwdate_watcher.fileChanged.connect(self.status_changed)

        self.anon_sdwdate_watcher = QFileSystemWatcher([self.anon_status_path])
        self.anon_sdwdate_watcher.fileChanged.connect(self.anon_vm_status_changed)

        exit_icon = QtGui.QIcon(self.icon_path + 'application-exit.png')
        self.exit_action = QAction(exit_icon, "&Exit", self)
        self.exit_action.triggered.connect(sys.exit)

        self.menu = QMenu()
        self.menu_list = []
        self.create_menu()
        self.setContextMenu(self.menu)
        self.activated.connect(self.show_menu)

        self.tor_status_changed()
        self.status_changed()

        self.anon_watch_thread = AnonVmWatcher(self, self.domain_list)
        self.anon_watch_thread.signal.connect(self.remove_vm)

        self.timer = QTimer()
        self.timer.timeout.connect(self.watch_anon_vms)
        self.timer.start(10000)

    def show_menu(self, event):
        if event == self.Trigger:
            self.menu.exec_(QtGui.QCursor.pos())

    def watch_anon_vms(self):
        self.anon_watch_thread.start()

    def create_sub_menu(self, menu):
        advanced_icon = QtGui.QIcon(self.icon_path + 'advancedsettings.ico')

        if menu.title() == self.name:
            icon = QtGui.QIcon(self.tor_icon[self.tor_status_list.index(self.tor_status)])
            action = QtWidgets.QAction(icon, 'Show Tor status', self)
            action.setEnabled(anon_connection_wizard_installed)
            action.triggered.connect(lambda: self.show_message(menu.title(), 'tor'))
            menu.addAction(action)
            action = QtWidgets.QAction(advanced_icon, 'Tor control panel', self)
            action.setEnabled(anon_connection_wizard_installed)
            action.triggered.connect(self.show_tor_status)
            menu.addAction(action)
            menu.addSeparator()

        icon = QtGui.QIcon(self.domain_icon_list[self.domain_list.index(menu.title())])
        action = QtWidgets.QAction(icon, 'Show sdwdate status', self)
        action.triggered.connect(lambda: self.show_message(menu.title(), 'sdwdate'))
        menu.addAction(action)

        menu.addSeparator()

        icon = QtGui.QIcon(self.icon_path + 'sdwdate-log.png')
        action = QtWidgets.QAction(icon, "Open sdwdate's log", self)
        action.triggered.connect(lambda: self.show_sdwdate_log(menu.title()))
        menu.addAction(action)

        icon = QtGui.QIcon(self.icon_path + 'restart-sdwdate.png')
        text = 'Restart sdwdate'
        action = QtWidgets.QAction(icon, text, self)
        action.triggered.connect(lambda: self.restart_sdwdate(menu.title()))
        menu.addAction(action)

        icon = QtGui.QIcon(self.icon_path + 'stop-sdwdate.png')
        action = QtWidgets.QAction(icon, "Stop sdwdate", self)
        action.triggered.connect(lambda: self.stop_sdwdate(menu.title()))
        menu.addAction(action)

    def create_menu(self):
        for vm in self.domain_list:
            if vm == self.name and (self.tor_status == 'stopped' or self.tor_status == 'disabled'):
                icon = QtGui.QIcon(self.tor_icon[self.tor_status_list.index(self.tor_status)])
            else:
                icon = QtGui.QIcon(self.domain_icon_list[self.domain_list.index(vm)])
            menu_item = self.menu.addMenu(icon, vm)
            self.menu_list.append(menu_item)
            if vm == self.name:
                self.menu.addSeparator()
            self.create_sub_menu(menu_item)

        self.menu.addAction(self.exit_action)

    def update_menu(self, vm, action):
        self.menu.removeAction(self.exit_action)

        #print("update_menu:")
        #print("vm:")
        #print(vm)

        ## remove _shutdown
        vm = vm.rsplit('_', 1)[0]
        #print(vm)
        sdwdate_icon = QtGui.QIcon(self.domain_icon_list[self.domain_list.index(vm)])
        tor_icon = QtGui.QIcon(self.tor_icon[self.tor_status_list.index(self.tor_status)])

        #print("action:")
        #print(action)

        if action == 'update':
            for item in self.menu_list:
                if item.title() == vm:
                    if vm == self.name:
                        if self.tor_status == 'running':
                            item.setIcon(sdwdate_icon)
                        elif not self.tor_status == 'running':
                            item.setIcon(tor_icon)
                        item.actions()[0].setIcon(tor_icon)
                        item.actions()[3].setIcon(sdwdate_icon)
                    else:
                        item.setIcon(sdwdate_icon)
                        item.actions()[0].setIcon(sdwdate_icon)

        elif action == 'add':
            menu_item = self.menu.addMenu(sdwdate_icon, vm)
            self.menu_list.append(menu_item)
            self.create_sub_menu(menu_item)

        elif action == 'remove':
            for item in self.menu_list:
                if item.title() == vm:
                    item.clear()
                    item.deleteLater()

        self.menu.addAction(self.exit_action)

    def run_popup(self, vm, caller):
        index = self.domain_list.index(vm)
        status = self.domain_message_list[index]

        if caller == 'tor':
            popup_process_cmd = ('%s %s %s %s' % (self.show_message_path, self.pos_x, self.pos_y,
                    '"%s" "%s"' % (self.tor_message, self.tor_icon[self.tor_status_list.index(self.tor_status)])))
        elif caller == 'sdwdate':
            popup_process_cmd = ('%s %s %s %s' % (self.show_message_path, self.pos_x, self.pos_y,
                    '"Last message from<b> %s </b> sdwdate:<br><br>%s" "%s"' % (vm, status,
                    self.domain_icon_list[self.domain_list.index(vm)])))

        self.popup_process = QProcess()
        self.popup_process.start(popup_process_cmd)

    def show_message(self, vm, caller):
        self.set_current_vm(vm)
        ## Store own position for message gui.
        if not self.clicked_once:
            self.pos_x = QtGui.QCursor.pos().x() - 50
            self.pos_y = QtGui.QCursor.pos().y() - 50
            self.clicked_once = True

        if self.popup_process == None:
            self.run_popup(vm, caller)
            return

        if self.popup_process.pid() > 0:
            self.popup_process.kill()
            self.popup_process = None
            self.run_popup(vm, caller)
        else:
            self.run_popup(vm, caller)

    def update_tip(self, vm, caller):
        if self.popup_process == None:
            return

        ## Update message only if already shown.
        if self.popup_process.pid() > 0:
            self.show_message(self.current_vm, caller)

    def set_current_vm(self, vm):
        ''' for update_tip,
        '''
        self.current_vm = vm

    def set_tray_icon(self):
        status_index = 0

        for status in self.domain_status_list:
            if self.status.index(status) > status_index:
                status_index = self.status.index(status)

        if self.tor_status == 'running':
            self.setIcon(QtGui.QIcon(self.icon[status_index]))
        else:
            self.setIcon(QtGui.QIcon(self.tor_icon[self.tor_status_list.index(self.tor_status)]))

    def remove_vm(self, vm):
        name = vm.rsplit('_', 1)[0]

        if name in self.domain_list:
            self.update_menu(vm, 'remove')
            index = self.domain_list.index(name)
            self.domain_list.pop(index)
            self.domain_status_list.pop(index)
            self.domain_icon_list.pop(index)
            self.domain_message_list.pop(index)
            self.menu_list.pop(index)

            self.set_tray_icon()

    def parse_sdwdate_status(self, vm, status, message):
        #print("parse_sdwdate_status:")
        #print(vm + " | " + status + " | " + message)

        icon = self.icon[self.status.index(status)]

        if vm not in self.domain_list:
            self.domain_list.append(vm)
            self.domain_status_list.append(status)
            self.domain_icon_list.append(icon)
            self.domain_message_list.append(message)
            self.update_menu(vm, 'add')

        else:
            index = self.domain_list.index(vm)
            self.domain_status_list[index] = status
            self.domain_icon_list[index] = icon
            self.domain_message_list[index] = message
            self.update_menu(vm, 'update')

        self.update_tip(vm, 'sdwdate')
        self.set_tray_icon()

    def parse_tor_status(self):
        if self.tor_status == '':
            return

        if self.tor_status == 'running':
            self.tor_message = 'Tor is running.'

        elif self.tor_status == 'disabled':
            self.tor_message = '<b>Tor is disabled</b>. Therefore you most likely<br> \
            can not connect to the internet. <br><br> \
            Run <b>Anon Connection Wizard</b> from the menu'

        elif self.tor_status == 'stopped':
            self.tor_message = '<b>Tor is not running.</b> <br><br> \
            You have to fix this error, before you can use Tor. <br> \
            Please restart Tor after fixing this error. <br><br> \
            dom0 -> Start Menu -> ServiceVM: sys-whonix -> Restart Tor GUI<br> \
            or in Terminal: <br> \
            sudo service tor@default restart <br><br> '

        elif self.tor_status == 'disabled-running':
            self.tor_message = '<b>Tor is running but is disabled.</b><br><br> \
            A line <i>DisableNetwork 1</i> exists in torrc <br> \
            Run <b>Anon Connection Wizard</b> from the menu <br>\
            to connect to or configure the Tor network.'

        self.update_tip(self.name, 'tor')
        self.update_menu(self.name, 'update')
        self.set_tray_icon()

    def anon_vm_status_changed(self):
        ## Fallbacks.
        vm_name = ''
        keyword = ''

        #print("#####")

        with open(self.anon_status_path, 'r') as f:
            #print("anon_vm_status_changed: file_content:")
            file_content = f.read().strip()
            #print(file_content)

            # Splitting file content and handling possible errors
            content_parts = file_content.split()
            if content_parts:
                vm_name = content_parts[0]
                #print("vm_name:")
                #print(vm_name)
                if len(content_parts) > 1:
                    keyword = content_parts[1]
                    #print("keyword:")
                    #print(keyword)
                else:
                    print("anon_vm_status_changed: No keyword found in file.")
            else:
                #print("File content is empty or has no spaces.")
                ## This happens after the file is truncated because it is being rewritten.
                return

        if not vm_name:
            #print("anon_vm_status_changed unexpected error: vm_name is empty")
            return

        if keyword == 'shutdown':
            self.remove_vm(vm_name)
            return

        try:
            command = ['qrexec-client-vm', vm_name, 'whonix.SdwdateStatus']
            p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            try:
                stdout, stderr = p.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                print(f"anon_vm_status_changed: Timeout: Command '{' '.join(command)}' timed out after 5 seconds.")
                return
        except Exception as e:
            error_msg = "anon_vm_status_changed: Error executing subprocess: " + str(e)
            print(error_msg)
            return

        #print("stdout:")
        #print(stdout)
        #print("stderr:")
        #print(stderr)

        try:
            status = json.loads(stdout.decode())
        except json.JSONDecodeError as e:
            error_msg = "Error parsing JSON: " + str(e)
            print(error_msg)
            return
        except Exception as e:
            error_msg = "Unexpected error during JSON parsing: " + str(e)
            print(error_msg)
            return

        #print(status['message'])

        self.parse_sdwdate_status(vm_name, status['icon'], status['message'])

    def status_changed(self):
        with open(self.status_path, 'r') as f:
            #print("status_changed: file_content:")
            file_content = f.read().strip()
            #print(file_content)

        if not file_content:
            #print("status_changed: File is empty or truncated.")
            return

        try:
            status = json.loads(file_content)
        except json.JSONDecodeError as e:
            error_msg = "status_changed: Error parsing JSON: " + str(e)
            print(error_msg)
            return
        except Exception as e:
            error_msg = "status_changed: Unexpected error during JSON parsing: " + str(e)
            print(error_msg)
            return

        self.parse_sdwdate_status(self.name, status['icon'], status['message'])

    def tor_status_changed(self):
        if not anon_connection_wizard_installed:
            ## tor_status() unavailable.
            return

        try:
            tor_is_enabled = tor_status.tor_status() == 'tor_enabled'
            tor_is_running = os.path.exists(self.tor_running_path)
        except:
            error_msg = "tor_status_changed unexpected error: " + str(sys.exc_info()[0])
            print(error_msg)
            return

        if tor_is_enabled and tor_is_running:
            self.tor_status = 'running'
        elif not tor_is_enabled:
            if tor_is_running:
                self.tor_status = 'disabled-running'
            elif not tor_is_running:
                self.tor_status = 'disabled'
        elif not tor_is_running:
            self.tor_status = 'stopped'

        self.parse_tor_status()

    def show_tor_status(self):
        command = 'tor-control-panel'
        subprocess.Popen(command.split(), shell=False)

    def show_sdwdate_log(self, vm):
        if vm == self.name:
            command = '/usr/libexec/sdwdate-gui/log-viewer'
        else:
            command = f'qrexec-client-vm {vm} whonix.GatewayCommand+showlog'
        print(f"show_tor_status: command: {command}")
        subprocess.Popen(command.split(), shell=False)

    def restart_sdwdate(self, vm):
        if self.tor_status == 'running':
            if vm == self.name:
                command = 'leaprun sdwdate-clock-jump'
            else:
                command = f'qrexec-client-vm {vm} whonix.GatewayCommand+restart'
            print(f"restart_sdwdate: command: {command}")
            subprocess.Popen(command.split(), shell=False)

    def stop_sdwdate(self, vm):
        if self.tor_status == 'running':
            if vm == self.name:
                command = 'leaprun stop-sdwdate'
            else:
                command = f'qrexec-client-vm {vm} whonix.GatewayCommand+stop'
            print(f"stop_sdwdate: command: {command}")
            subprocess.Popen(command.split(), shell=False)

def signal_handler(sig, frame):
    sys.exit(128 + sig)

def main():
    app = QtWidgets.QApplication(["Sdwdate"])

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    timer = QtCore.QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    sdwdate_tray = SdwdateTrayIcon()
    sdwdate_tray.show()
    app.exec_()

if __name__ == "__main__":
    main()
