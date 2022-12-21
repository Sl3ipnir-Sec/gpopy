import asyncio
import logging
import re
from gpopy.task import ScheduledTask
from gpopy.ldap import Ldap


class GPO:
    def __init__(self, smb_session):
        self._smb_session = smb_session

    def update_extensionNames(self, extensionName):
        val1 = "00000000-0000-0000-0000-000000000000"
        val2 = "CAB54552-DEEA-4691-817E-ED4A4D1AFC72"
        val3 = "AADCED64-746C-4633-A97C-D61349046527"

        if extensionName is None:
            extensionName = ""

        try:
            if val2 not in extensionName:
                new_values = []
                toUpdate = ''.join(extensionName)
                test = toUpdate.split("[")
                for i in test:
                    new_values.append(i.replace("{", "").replace("}", " ").replace("]", ""))

                if val1 not in toUpdate:
                    new_values.append(val1 + " " + val2)

                elif val1 in toUpdate:
                    for k, v in enumerate(new_values):
                        if val1 in new_values[k]:
                            toSort = []
                            test2 = new_values[k].split()
                            for f in range(1, len(test2)):
                                toSort.append(test2[f])
                            toSort.append(val2)
                            toSort.sort()
                            new_values[k] = test2[0]
                            for val in toSort:
                                new_values[k] += " " + val

                if val3 not in toUpdate:
                    new_values.append(val3 + " " + val2)

                elif val3 in toUpdate:
                    for k, v in enumerate(new_values):
                        if val3 in new_values[k]:
                            toSort = []
                            test2 = new_values[k].split()
                            for f in range(1, len(test2)):
                                toSort.append(test2[f])
                            toSort.append(val2)
                            toSort.sort()
                            new_values[k] = test2[0]
                            for val in toSort:
                                new_values[k] += " " + val

                new_values.sort()

                new_values2 = []
                for i in range(len(new_values)):
                    if new_values[i] is None or new_values[i] == "":
                        continue
                    value1 = new_values[i].split()
                    new_val = ""
                    for q in range(len(value1)):
                        if value1[q] is None or value1[q] == "":
                            continue
                        new_val += "{" + value1[q] + "}"
                    new_val = "[" + new_val + "]"
                    new_values2.append(new_val)

                return "".join(new_values2)
        # TODO: Remove potential for massive mess-making here
        except:
            return "[{" + val1 + "}{" + val2 + "}]" + "[{" + val3 + "}{" + val2 + "}]"

    async def ldap_find_user(self, url, domain, gpo_id, user):
        ldap = Ldap(url, gpo_id, domain)
        r = await ldap.connect()
        if not r:
            print("LDAP connection failed")
            return False
        user = await ldap.find_user(user)
        if not user:
            return False
        return user

    async def update_ldap(self, url, domain, gpo_id, gpo_type="computer", extensions=False):
        ldap = Ldap(url, gpo_id, domain)
        r = await ldap.connect()
        if not r:
            print("Could not connect to LDAP")
            return False

        version = await ldap.get_attribute("versionNumber")
        if not version:
            print("Could not get versionNumber attribute")
            return False

        attribute_name = "gPCMachineExtensionNames"
        updated_version = version + 1
        if extensions:
            extensionName = await ldap.get_attribute(attribute_name)

            if extensionName == False:
                print("Could not get {} attribute".format(attribute_name))
                return False

            updated_extensionName = self.update_extensionNames(extensionName)

            print("New extensionName: {}".format(updated_extensionName))

            await ldap.update_attribute(attribute_name, updated_extensionName, extensionName)
        await ldap.update_attribute("versionNumber", updated_version, version)

        return updated_version

    def update_versions(self, url, domain, gpo_id, gpo_type, extensions=False):
        updated_version = asyncio.run(self.update_ldap(url, domain, gpo_id, gpo_type, extensions))

        if not updated_version:
            return False

        print("Updated version number : {}".format(updated_version))

        try:
            tid = self._smb_session.connectTree("SYSVOL")
            fid = self._smb_session.openFile(tid, domain + "/Policies/{" + gpo_id + "}/gpt.ini")
            content = self._smb_session.readFile(tid, fid)

            new_content = re.sub('=[0-9]+', '={}'.format(updated_version), content.decode("utf-8"))
            self._smb_session.writeFile(tid, fid, new_content)
            self._smb_session.closeFile(tid, fid)
        except:
            print("Unable to update gpt.ini file")
            return False

        print("gpt.ini file successfully updated")
        return True

    def _check_or_create(self, base_path, path):
        for dir in path.split("/"):
            base_path += dir + "/"
            try:
                self._smb_session.listPath("SYSVOL", base_path)
                print("{} exists".format(base_path))
            except:
                try:
                    self._smb_session.createDirectory("SYSVOL", base_path)
                    print("{} created".format(base_path))
                except:
                    print("This user doesn't seem to have the necessary rights")
                    return False
        return True

    def add_local_admin(self, url, domain, gpo_id, username, force):
        # Do stuff
        logging.info("Attempting to add new local admin")
        user = asyncio.run(self.ldap_find_user(url, domain, gpo_id, username))
        if not user:
            print("Couldn't find SID for user {}".format(username))
        sid = user[0].objectSid
        logging.info("SID for user {} is {}".format(username, sid))
        try:
            tid = self._smb_session.connectTree("SYSVOL")
            print("Connected to SYSVOL")
        except:
            print("Unable to connect to SYSVOL share")
            return False
        path = domain + "/Policies/{" + gpo_id + "}/"
        start = f"""[Unicode]
                    Unicode=yes
                    [Version]
                    signature=""$CHICAGO$""
                    Revision=1"""
        gpt_path = path + "gpt.ini"
        text = f"""[Group Membership]
*S-1-5-32-544__Memberof =
*S-1-5-32-544__Members = * {sid}
                """
        try:
            self._smb_session.listPath("SYSVOL", path)
            print("GPO id {} exists".format(gpo_id))
        except:
            print("GPO id {} does not exist".format(gpo_id))
            return False
        secedit = path + "Machine/Microsoft/Windows NT/SecEdit/"
        try:
            self._smb_session.listPath("SYSVOL", secedit)
            print("SecEdit path exists")
        except:
            print("SecEdit path doesn't exist!")
            return False
        gpttmpl = secedit + "GptTmpl.inf"
        try:
            fid = self._smb_session.openFile(tid, gpttmpl)
            f_content = self._smb_session.readFile(tid, fid, singleCall=False).decode("utf-16")
            exists = False

            to_write = []
            for line in f_content.split("\r\n"):
                if "[Group Membership]" in line:
                    exists = True
            if exists and not force:
                print("Group Memberships are already defined in the GPO, use --force to make changes. "
                                  "Beware!")
                return False
            if exists and force:
                for line in f_content:
                    if "*S-1-5-32-544__Members=" in line.strip():
                        if "*S-1-5-32-544__Members=" in line.strip() and line.strip() == "*S-1-5-32-544__Members=":
                            to_write.append(line + " *" + sid)
                        elif "*S-1-5-32-544__Members=" in line.strip() and len(line.strip()) > len("*S-1-5-32-544__Members="):
                            to_write.append(line + ", *" + sid)
                    else:
                        to_write.append(line)
            if not exists:
                print("The GPO does not specify group memberships")
                for line in f_content.split("\r\n"):
                    to_write.append(line+"\r\n")
                to_write.append(text)
            self._smb_session.writeFile(tid, fid, ''.join(to_write).encode('utf-16'))
            self.update_versions(url, domain, gpo_id, "Computer")
            self._smb_session.closeFile(tid, fid)
            return True

        # TODO: Fix naked except
        except Exception as e:
            # File does not exist
            print("GptTmpl.inf does not exist. Creating it...")
            try:
                fid = self._smb_session.createFile(tid, path)
                print("GptTmpl.inf created")
            except:
                print("This user doesn't seem to have the necessary rights")
                return False
            try:
                self._smb_session.writeFile(tid, fid, start + "\n" + text)
                print("GptTmpl.inf has been saved")
            except:
                print("This user doesn't seem to have the necessary rights")
                self._smb_session.closeFile(tid, fid)
                return False
        self._smb_session.closeFile(tid, fid)
        self.update_versions(url, domain, gpo_id, "Computer")
        return True

    def update_scheduled_task(self, domain, gpo_id, task_name="", command="", arguments="",
                              description="", force=False, admin_username="", admin_password="", author="",
                              computer_task=True):

        try:
            tid = self._smb_session.connectTree("SYSVOL")
            print("Connected to SYSVOL")
        except:
            print("Unable to connect to SYSVOL share")
            return False

        path = domain + "/Policies/{" + gpo_id + "}/"

        try:
            self._smb_session.listPath("SYSVOL", path)
            print("GPO id {} exists".format(gpo_id))
        except:
            print("GPO id {} does not exist".format(gpo_id))
            return False
        if computer_task:
            root_path = "Machine"
        else:
            root_path = "User"

        if not self._check_or_create(path, "{}/Preferences/ScheduledTasks".format(root_path)):
            return False

        path += "{}/Preferences/ScheduledTasks/ScheduledTasks.xml".format(root_path)

        try:
            fid = self._smb_session.openFile(tid, path)
            st_content = self._smb_session.readFile(tid, fid, singleCall=False).decode("utf-8")
            st = ScheduledTask(computer_task=computer_task, name=task_name, command=command, arguments=arguments,
                               description=description, admin_username=admin_username, admin_password=admin_password,
                               author=author, old_value=st_content)
            tasks = st.parse_tasks(st_content)

            if not force:
                print("The GPO already includes a ScheduledTasks.xml.")
                print("Use -f to append to ScheduledTasks.xml")
                print("Use -v to display existing tasks")
                logging.warning("C: Create, U: Update, D: Delete, R: Replace")
                for task in tasks:
                    logging.warning("[{}] {} (Type: {})".format(task[0], task[1], task[2]))
                return False

            new_content = st.generate_scheduled_task_xml()
        except Exception as e:
            # File does not exist
            print("ScheduledTasks.xml does not exist. Creating it...")
            try:
                fid = self._smb_session.createFile(tid, path)
                print("ScheduledTasks.xml created")
            except:
                print("This user doesn't seem to have the necessary rights")
                return False
            st = ScheduledTask(description=description)
            new_content = st.generate_scheduled_task_xml()

        try:
            self._smb_session.writeFile(tid, fid, new_content)
            print("ScheduledTasks.xml has been saved")
        except:
            print("This user doesn't seem to have the necessary rights")
            self._smb_session.closeFile(tid, fid)
            return False
        self._smb_session.closeFile(tid, fid)
        return st.get_name()
