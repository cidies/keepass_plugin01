using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Security;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace keepass_plugin01
{
    public sealed class keepass_plugin01Ext : Plugin
    {
        private const string ContainerFormat = "KeePassRecordExchange";
        private const int ContainerVersion = 1;
        private const int Pbkdf2Iterations = 600000;
        private const int ClipboardLifetimeSeconds = 30;
        private const int MaximumContainerCharacters = 140000000;
        private const long MaximumFileBytes = 100L * 1024L * 1024L;

        private static readonly byte[] AssociatedData =
            Encoding.UTF8.GetBytes("KeePassRecordExchange|1");

        private IPluginHost pluginHost;
        private Timer clipboardTimer;
        private string lastClipboardValue;

        public override bool Initialize(IPluginHost host)
        {
            if (host == null)
                return false;

            pluginHost = host;

            clipboardTimer = new Timer();
            clipboardTimer.Interval = ClipboardLifetimeSeconds * 1000;
            clipboardTimer.Tick += ClipboardTimerTick;

            return true;
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType type)
        {
            if (type != PluginMenuType.Main &&
                type != PluginMenuType.Entry)
            {
                return null;
            }

            ToolStripMenuItem root =
                new ToolStripMenuItem("Record Exchange");

            ToolStripMenuItem copy =
                new ToolStripMenuItem("COPY RECORD ENCRYPTED");

            ToolStripMenuItem paste =
                new ToolStripMenuItem("PASTE RECORD ENCRYPTED");

            ToolStripMenuItem exportFile =
                new ToolStripMenuItem("EXPORT RECORD TO FILE");

            ToolStripMenuItem importFile =
                new ToolStripMenuItem("IMPORT RECORD FROM FILE");

            copy.Click += CopyEncrypted;
            paste.Click += PasteEncrypted;
            exportFile.Click += ExportEncryptedFile;
            importFile.Click += ImportEncryptedFile;

            root.DropDownItems.Add(copy);
            root.DropDownItems.Add(paste);
            root.DropDownItems.Add(new ToolStripSeparator());
            root.DropDownItems.Add(exportFile);
            root.DropDownItems.Add(importFile);

            return root;
        }

        private void CopyEncrypted(object sender, EventArgs e)
        {
            try
            {
                List<RecordData> records = GetSelectedRecords();
                if (records == null)
                    return;

                string password;
                if (!PasswordDialog.Request(
                    pluginHost.MainWindow,
                    "COPY RECORD ENCRYPTED",
                    true,
                    out password))
                {
                    return;
                }

                string container;
                try
                {
                    container = CreateEncryptedContainer(records, password);
                }
                finally
                {
                    password = null;
                }

                SetSensitiveClipboard(container);

                MessageBox.Show(
                    pluginHost.MainWindow,
                    records.Count +
                    " Datensätze wurden verschlüsselt in die " +
                    "Zwischenablage kopiert.\r\n\r\n" +
                    "Automatische Löschung nach " +
                    ClipboardLifetimeSeconds + " Sekunden.",
                    "COPY RECORD ENCRYPTED",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                ShowError("Die Datensätze konnten nicht kopiert werden.", ex);
            }
        }

        private void PasteEncrypted(object sender, EventArgs e)
        {
            try
            {
                EnsureDatabaseOpen();

                if (!Clipboard.ContainsText())
                {
                    MessageBox.Show(
                        pluginHost.MainWindow,
                        "Die Zwischenablage enthält keinen Text.",
                        "PASTE RECORD ENCRYPTED",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    return;
                }

                string container = Clipboard.GetText();
                ValidateContainerLength(container);

                string password;
                if (!PasswordDialog.Request(
                    pluginHost.MainWindow,
                    "PASTE RECORD ENCRYPTED",
                    false,
                    out password))
                {
                    return;
                }

                List<RecordData> records;
                try
                {
                    records = DecryptContainer(container, password);
                }
                finally
                {
                    password = null;
                }

                int count = ImportRecords(records);
                ClearClipboardIfUnchanged(container);

                MessageBox.Show(
                    pluginHost.MainWindow,
                    count + " Datensätze wurden erfolgreich angelegt.",
                    "PASTE RECORD ENCRYPTED",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (InvalidCipherTextException)
            {
                ShowAuthenticationError();
            }
            catch (CryptographicException)
            {
                ShowAuthenticationError();
            }
            catch (Exception ex)
            {
                ShowError("Die Datensätze konnten nicht eingefügt werden.", ex);
            }
        }

        private void ExportEncryptedFile(object sender, EventArgs e)
        {
            try
            {
                List<RecordData> records = GetSelectedRecords();
                if (records == null)
                    return;

                string password;
                if (!PasswordDialog.Request(
                    pluginHost.MainWindow,
                    "EXPORT RECORD TO FILE",
                    true,
                    out password))
                {
                    return;
                }

                string container;
                try
                {
                    container = CreateEncryptedContainer(records, password);
                }
                finally
                {
                    password = null;
                }

                using (SaveFileDialog dialog = new SaveFileDialog())
                {
                    dialog.Title = "Verschlüsselte KeePass-Datensätze exportieren";
                    dialog.Filter =
                        "KeePass Record Exchange (*.kprx)|*.kprx|Alle Dateien (*.*)|*.*";
                    dialog.DefaultExt = "kprx";
                    dialog.AddExtension = true;
                    dialog.OverwritePrompt = true;
                    dialog.FileName = "KeePassRecords.kprx";

                    if (dialog.ShowDialog(pluginHost.MainWindow) !=
                        DialogResult.OK)
                    {
                        return;
                    }

                    WriteFileAtomically(dialog.FileName, container);

                    MessageBox.Show(
                        pluginHost.MainWindow,
                        records.Count +
                        " Datensätze wurden verschlüsselt exportiert.",
                        "EXPORT RECORD TO FILE",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                ShowError("Die Exportdatei konnte nicht erstellt werden.", ex);
            }
        }

        private void ImportEncryptedFile(object sender, EventArgs e)
        {
            try
            {
                EnsureDatabaseOpen();

                using (OpenFileDialog dialog = new OpenFileDialog())
                {
                    dialog.Title = "Verschlüsselte KeePass-Datensätze importieren";
                    dialog.Filter =
                        "KeePass Record Exchange (*.kprx)|*.kprx|Alle Dateien (*.*)|*.*";
                    dialog.CheckFileExists = true;
                    dialog.Multiselect = false;

                    if (dialog.ShowDialog(pluginHost.MainWindow) !=
                        DialogResult.OK)
                    {
                        return;
                    }

                    FileInfo fileInfo = new FileInfo(dialog.FileName);
                    if (fileInfo.Length > MaximumFileBytes)
                    {
                        throw new InvalidOperationException(
                            "Die Datei überschreitet die zulässige Größe von 100 MB.");
                    }

                    string container = File.ReadAllText(
                        dialog.FileName,
                        Encoding.UTF8);

                    ValidateContainerLength(container);

                    string password;
                    if (!PasswordDialog.Request(
                        pluginHost.MainWindow,
                        "IMPORT RECORD FROM FILE",
                        false,
                        out password))
                    {
                        return;
                    }

                    List<RecordData> records;
                    try
                    {
                        records = DecryptContainer(container, password);
                    }
                    finally
                    {
                        password = null;
                    }

                    int count = ImportRecords(records);

                    MessageBox.Show(
                        pluginHost.MainWindow,
                        count + " Datensätze wurden erfolgreich importiert.",
                        "IMPORT RECORD FROM FILE",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
            }
            catch (InvalidCipherTextException)
            {
                ShowAuthenticationError();
            }
            catch (CryptographicException)
            {
                ShowAuthenticationError();
            }
            catch (Exception ex)
            {
                ShowError("Die Exportdatei konnte nicht importiert werden.", ex);
            }
        }

        private List<RecordData> GetSelectedRecords()
        {
            PwEntry[] selectedEntries =
                pluginHost.MainWindow.GetSelectedEntries();

            if (selectedEntries == null || selectedEntries.Length == 0)
            {
                MessageBox.Show(
                    pluginHost.MainWindow,
                    "Bitte mindestens einen KeePass-Eintrag auswählen.",
                    "Record Exchange",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return null;
            }

            List<RecordData> records = new List<RecordData>();
            foreach (PwEntry entry in selectedEntries)
                records.Add(CreateRecordData(entry));

            return records;
        }

        private string CreateEncryptedContainer(
            List<RecordData> records,
            string password)
        {
            JavaScriptSerializer serializer = CreateSerializer();
            string payloadJson = serializer.Serialize(records);
            byte[] plaintext = Encoding.UTF8.GetBytes(payloadJson);
            byte[] salt = RandomBytes(16);
            byte[] nonce = RandomBytes(12);
            byte[] key = null;
            byte[] cipherText = null;

            try
            {
                key = DeriveKey(password, salt, Pbkdf2Iterations);
                cipherText = EncryptAesGcm(plaintext, key, nonce);

                EncryptedEnvelope envelope = new EncryptedEnvelope();
                envelope.Format = ContainerFormat;
                envelope.Version = ContainerVersion;
                envelope.Kdf = "PBKDF2-HMAC-SHA256";
                envelope.Iterations = Pbkdf2Iterations;
                envelope.Salt = Convert.ToBase64String(salt);
                envelope.Cipher = "AES-256-GCM";
                envelope.Nonce = Convert.ToBase64String(nonce);
                envelope.Ciphertext = Convert.ToBase64String(cipherText);

                return serializer.Serialize(envelope);
            }
            finally
            {
                ClearBytes(plaintext);
                ClearBytes(key);
                ClearBytes(cipherText);
                ClearBytes(salt);
                ClearBytes(nonce);
                payloadJson = null;
            }
        }

        private List<RecordData> DecryptContainer(
            string container,
            string password)
        {
            ValidateContainerLength(container);

            JavaScriptSerializer serializer = CreateSerializer();
            EncryptedEnvelope envelope =
                serializer.Deserialize<EncryptedEnvelope>(container);

            ValidateEnvelope(envelope);

            byte[] salt = null;
            byte[] nonce = null;
            byte[] cipherText = null;
            byte[] key = null;
            byte[] plaintext = null;

            try
            {
                salt = Convert.FromBase64String(envelope.Salt);
                nonce = Convert.FromBase64String(envelope.Nonce);
                cipherText = Convert.FromBase64String(envelope.Ciphertext);

                if (salt.Length != 16 ||
                    nonce.Length != 12 ||
                    cipherText.Length < 16)
                {
                    throw new CryptographicException(
                        "Ungültige kryptografische Parameter.");
                }

                key = DeriveKey(password, salt, envelope.Iterations);
                plaintext = DecryptAesGcm(cipherText, key, nonce);

                string payloadJson = Encoding.UTF8.GetString(plaintext);
                List<RecordData> records =
                    serializer.Deserialize<List<RecordData>>(payloadJson);
                payloadJson = null;

                ValidateRecords(records);
                return records;
            }
            catch (FormatException ex)
            {
                throw new CryptographicException(
                    "Ungültige Container-Kodierung.", ex);
            }
            finally
            {
                ClearBytes(salt);
                ClearBytes(nonce);
                ClearBytes(cipherText);
                ClearBytes(key);
                ClearBytes(plaintext);
            }
        }

        private static byte[] DeriveKey(
            string password,
            byte[] salt,
            int iterations)
        {
            using (Rfc2898DeriveBytes kdf =
                new Rfc2898DeriveBytes(
                    password,
                    salt,
                    iterations,
                    HashAlgorithmName.SHA256))
            {
                return kdf.GetBytes(32);
            }
        }

        private static byte[] EncryptAesGcm(
            byte[] plaintext,
            byte[] key,
            byte[] nonce)
        {
            GcmBlockCipher cipher =
                new GcmBlockCipher(new AesEngine());

            AeadParameters parameters = new AeadParameters(
                new KeyParameter(key),
                128,
                nonce,
                AssociatedData);

            cipher.Init(true, parameters);

            byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];
            int length = cipher.ProcessBytes(
                plaintext,
                0,
                plaintext.Length,
                output,
                0);

            length += cipher.DoFinal(output, length);

            if (length == output.Length)
                return output;

            byte[] result = new byte[length];
            Buffer.BlockCopy(output, 0, result, 0, length);
            ClearBytes(output);
            return result;
        }

        private static byte[] DecryptAesGcm(
            byte[] cipherText,
            byte[] key,
            byte[] nonce)
        {
            GcmBlockCipher cipher =
                new GcmBlockCipher(new AesEngine());

            AeadParameters parameters = new AeadParameters(
                new KeyParameter(key),
                128,
                nonce,
                AssociatedData);

            cipher.Init(false, parameters);

            byte[] output = new byte[cipher.GetOutputSize(cipherText.Length)];
            int length = cipher.ProcessBytes(
                cipherText,
                0,
                cipherText.Length,
                output,
                0);

            length += cipher.DoFinal(output, length);

            byte[] result = new byte[length];
            Buffer.BlockCopy(output, 0, result, 0, length);
            ClearBytes(output);
            return result;
        }

        private static byte[] RandomBytes(int length)
        {
            byte[] result = new byte[length];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                rng.GetBytes(result);
            return result;
        }

        private static void ClearBytes(byte[] value)
        {
            if (value != null)
                Array.Clear(value, 0, value.Length);
        }

        private static JavaScriptSerializer CreateSerializer()
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = MaximumContainerCharacters;
            serializer.RecursionLimit = 100;
            return serializer;
        }

        private static void ValidateEnvelope(EncryptedEnvelope envelope)
        {
            if (envelope == null ||
                envelope.Format != ContainerFormat ||
                envelope.Version != ContainerVersion ||
                envelope.Kdf != "PBKDF2-HMAC-SHA256" ||
                envelope.Cipher != "AES-256-GCM" ||
                envelope.Iterations < 100000 ||
                envelope.Iterations > 5000000 ||
                String.IsNullOrWhiteSpace(envelope.Salt) ||
                String.IsNullOrWhiteSpace(envelope.Nonce) ||
                String.IsNullOrWhiteSpace(envelope.Ciphertext))
            {
                throw new InvalidOperationException(
                    "Die Daten sind kein unterstützter KeePass-Record-Container.");
            }
        }

        private static void ValidateRecords(List<RecordData> records)
        {
            if (records == null || records.Count == 0)
            {
                throw new InvalidOperationException(
                    "Der Container enthält keine Datensätze.");
            }

            if (records.Count > 10000)
            {
                throw new InvalidOperationException(
                    "Der Container enthält zu viele Datensätze.");
            }

            foreach (RecordData record in records)
            {
                if (record == null || record.Fields == null)
                {
                    throw new InvalidOperationException(
                        "Der Container enthält einen ungültigen Datensatz.");
                }
            }
        }

        private static void ValidateContainerLength(string container)
        {
            if (String.IsNullOrWhiteSpace(container))
                throw new InvalidOperationException("Der Container ist leer.");

            if (container.Length > MaximumContainerCharacters)
            {
                throw new InvalidOperationException(
                    "Der Container überschreitet die zulässige Größe.");
            }
        }

        private void SetSensitiveClipboard(string value)
        {
            StopClipboardTimer();

            DataObject data = new DataObject();
            data.SetData(DataFormats.UnicodeText, value);

            // Diese von Windows definierten Formate verhindern nach Möglichkeit
            // die Aufnahme in Clipboard History und Cloud Clipboard.
            data.SetData(
                "ExcludeClipboardContentFromMonitorProcessing",
                false,
                new byte[] { 0 });
            data.SetData(
                "CanIncludeInClipboardHistory",
                false,
                new byte[] { 0, 0, 0, 0 });
            data.SetData(
                "CanUploadToCloudClipboard",
                false,
                new byte[] { 0, 0, 0, 0 });

            Clipboard.SetDataObject(data, true);

            lastClipboardValue = value;
            clipboardTimer.Start();
        }

        private void ClipboardTimerTick(object sender, EventArgs e)
        {
            StopClipboardTimer();
            ClearClipboardIfUnchanged(lastClipboardValue);
        }

        private void ClearClipboardIfUnchanged(string expectedValue)
        {
            try
            {
                if (!String.IsNullOrEmpty(expectedValue) &&
                    Clipboard.ContainsText() &&
                    String.Equals(
                        Clipboard.GetText(),
                        expectedValue,
                        StringComparison.Ordinal))
                {
                    Clipboard.Clear();
                }
            }
            catch
            {
                // Clipboard kann kurzzeitig von einem anderen Prozess gesperrt sein.
            }
            finally
            {
                if (String.Equals(
                    lastClipboardValue,
                    expectedValue,
                    StringComparison.Ordinal))
                {
                    lastClipboardValue = null;
                }
            }
        }

        private void StopClipboardTimer()
        {
            if (clipboardTimer != null)
                clipboardTimer.Stop();
        }

        private static void WriteFileAtomically(string path, string content)
        {
            string fullPath = Path.GetFullPath(path);
            string directory = Path.GetDirectoryName(fullPath);
            string temporaryPath = Path.Combine(
                directory,
                "." + Path.GetFileName(fullPath) + "." +
                Guid.NewGuid().ToString("N") + ".tmp");

            try
            {
                File.WriteAllText(
                    temporaryPath,
                    content,
                    new UTF8Encoding(false));

                if (File.Exists(fullPath))
                    File.Replace(temporaryPath, fullPath, null);
                else
                    File.Move(temporaryPath, fullPath);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                    File.Delete(temporaryPath);
            }
        }

        private void EnsureDatabaseOpen()
        {
            if (!pluginHost.Database.IsOpen)
            {
                throw new InvalidOperationException(
                    "Es ist keine KeePass-Datenbank geöffnet.");
            }
        }

        private int ImportRecords(List<RecordData> records)
        {
            ValidateRecords(records);

            PwGroup targetGroup = DetermineTargetGroup();
            if (targetGroup == null)
            {
                throw new InvalidOperationException(
                    "Es konnte keine Zielgruppe bestimmt werden.");
            }

            int importedCount = 0;

            foreach (RecordData record in records)
            {
                string originalTitle =
                    GetFieldValue(record, PwDefs.TitleField);

                string uniqueTitle =
                    CreateUniqueTitle(targetGroup, originalTitle);

                SetFieldValue(record, PwDefs.TitleField, uniqueTitle);

                PwEntry newEntry = CreateEntry(record);
                targetGroup.AddEntry(newEntry, true);
                importedCount++;
            }

            pluginHost.Database.Modified = true;

            pluginHost.MainWindow.UpdateUI(
                false, null,
                true, targetGroup,
                true, null,
                true);

            return importedCount;
        }

        private PwGroup DetermineTargetGroup()
        {
            PwEntry[] selectedEntries =
                pluginHost.MainWindow.GetSelectedEntries();

            if (selectedEntries != null &&
                selectedEntries.Length > 0 &&
                selectedEntries[0].ParentGroup != null)
            {
                return selectedEntries[0].ParentGroup;
            }

            PwGroup selectedGroup =
                pluginHost.MainWindow.GetSelectedGroup();

            if (selectedGroup != null)
                return selectedGroup;

            return pluginHost.Database.RootGroup;
        }

        private RecordData CreateRecordData(PwEntry entry)
        {
            RecordData record = new RecordData();
            record.Schema = "keepass-record";
            record.Version = 1;
            record.Fields = new List<FieldData>();
            record.Tags = new List<string>();
            record.Attachments = new List<AttachmentData>();
            record.Expires = entry.Expires;
            record.ExpiryTimeUtc =
                entry.ExpiryTime.ToUniversalTime().ToString("o");
            record.IconId = (int)entry.IconId;

            foreach (KeyValuePair<string, ProtectedString> item
                in entry.Strings)
            {
                record.Fields.Add(new FieldData
                {
                    Name = item.Key,
                    Value = item.Value.ReadString(),
                    Protected = item.Value.IsProtected
                });
            }

            foreach (string tag in entry.Tags)
                record.Tags.Add(tag);

            foreach (KeyValuePair<string, ProtectedBinary> item
                in entry.Binaries)
            {
                record.Attachments.Add(new AttachmentData
                {
                    Name = item.Key,
                    Protected = item.Value.IsProtected,
                    Base64 = Convert.ToBase64String(item.Value.ReadData())
                });
            }

            return record;
        }

        private PwEntry CreateEntry(RecordData record)
        {
            PwEntry entry = new PwEntry(true, true);
            entry.Strings.Clear();

            foreach (FieldData field in record.Fields)
            {
                if (field == null || String.IsNullOrEmpty(field.Name))
                    continue;

                entry.Strings.Set(
                    field.Name,
                    new ProtectedString(
                        field.Protected,
                        field.Value ?? String.Empty));
            }

            if (record.Tags != null)
            {
                foreach (string tag in record.Tags)
                {
                    if (!String.IsNullOrWhiteSpace(tag) &&
                        !entry.Tags.Contains(tag))
                    {
                        entry.Tags.Add(tag);
                    }
                }
            }

            entry.Expires = record.Expires;

            DateTime expiryTime;
            if (DateTime.TryParse(
                record.ExpiryTimeUtc,
                null,
                System.Globalization.DateTimeStyles.RoundtripKind,
                out expiryTime))
            {
                entry.ExpiryTime = expiryTime.ToLocalTime();
            }

            if (Enum.IsDefined(typeof(PwIcon), record.IconId))
                entry.IconId = (PwIcon)record.IconId;

            if (record.Attachments != null)
            {
                foreach (AttachmentData attachment in record.Attachments)
                {
                    if (attachment == null ||
                        String.IsNullOrEmpty(attachment.Name) ||
                        String.IsNullOrEmpty(attachment.Base64))
                    {
                        continue;
                    }

                    byte[] data =
                        Convert.FromBase64String(attachment.Base64);

                    try
                    {
                        entry.Binaries.Set(
                            attachment.Name,
                            new ProtectedBinary(attachment.Protected, data));
                    }
                    finally
                    {
                        ClearBytes(data);
                    }
                }
            }

            return entry;
        }

        private string CreateUniqueTitle(
            PwGroup group,
            string requestedTitle)
        {
            string title = String.IsNullOrWhiteSpace(requestedTitle)
                ? "Untitled"
                : requestedTitle;

            while (TitleExists(group, title))
                title += "_copy";

            return title;
        }

        private static bool TitleExists(PwGroup group, string title)
        {
            foreach (PwEntry entry in group.Entries)
            {
                string existingTitle =
                    entry.Strings.ReadSafe(PwDefs.TitleField);

                if (String.Equals(
                    existingTitle,
                    title,
                    StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static string GetFieldValue(
            RecordData record,
            string fieldName)
        {
            if (record.Fields == null)
                return String.Empty;

            foreach (FieldData field in record.Fields)
            {
                if (field != null &&
                    String.Equals(
                        field.Name,
                        fieldName,
                        StringComparison.Ordinal))
                {
                    return field.Value ?? String.Empty;
                }
            }

            return String.Empty;
        }

        private static void SetFieldValue(
            RecordData record,
            string fieldName,
            string value)
        {
            if (record.Fields == null)
                record.Fields = new List<FieldData>();

            foreach (FieldData field in record.Fields)
            {
                if (field != null &&
                    String.Equals(
                        field.Name,
                        fieldName,
                        StringComparison.Ordinal))
                {
                    field.Value = value;
                    return;
                }
            }

            record.Fields.Add(new FieldData
            {
                Name = fieldName,
                Value = value,
                Protected = false
            });
        }

        private void ShowAuthenticationError()
        {
            MessageBox.Show(
                pluginHost.MainWindow,
                "Das Passwort ist falsch oder der Container wurde verändert.",
                "KeePass Record Exchange",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }

        private void ShowError(string message, Exception exception)
        {
            MessageBox.Show(
                pluginHost.MainWindow,
                message + "\r\n\r\n" + exception.Message,
                "KeePass Record Exchange",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }

        public override void Terminate()
        {
            StopClipboardTimer();
            ClearClipboardIfUnchanged(lastClipboardValue);

            if (clipboardTimer != null)
            {
                clipboardTimer.Tick -= ClipboardTimerTick;
                clipboardTimer.Dispose();
                clipboardTimer = null;
            }

            lastClipboardValue = null;
            pluginHost = null;
        }

        public sealed class EncryptedEnvelope
        {
            public string Format { get; set; }
            public int Version { get; set; }
            public string Kdf { get; set; }
            public int Iterations { get; set; }
            public string Salt { get; set; }
            public string Cipher { get; set; }
            public string Nonce { get; set; }
            public string Ciphertext { get; set; }
        }

        public sealed class RecordData
        {
            public string Schema { get; set; }
            public int Version { get; set; }
            public List<FieldData> Fields { get; set; }
            public List<string> Tags { get; set; }
            public List<AttachmentData> Attachments { get; set; }
            public bool Expires { get; set; }
            public string ExpiryTimeUtc { get; set; }
            public int IconId { get; set; }
        }

        public sealed class FieldData
        {
            public string Name { get; set; }
            public string Value { get; set; }
            public bool Protected { get; set; }
        }

        public sealed class AttachmentData
        {
            public string Name { get; set; }
            public string Base64 { get; set; }
            public bool Protected { get; set; }
        }

        private sealed class PasswordDialog : Form
        {
            private readonly TextBox passwordBox;
            private readonly TextBox confirmationBox;
            private readonly bool requireConfirmation;

            private PasswordDialog(string title, bool confirmation)
            {
                requireConfirmation = confirmation;

                Text = title;
                StartPosition = FormStartPosition.CenterParent;
                FormBorderStyle = FormBorderStyle.FixedDialog;
                MaximizeBox = false;
                MinimizeBox = false;
                ShowInTaskbar = false;
                ClientSize = new Size(430, confirmation ? 190 : 145);

                Label explanation = new Label();
                explanation.AutoSize = false;
                explanation.Location = new Point(12, 12);
                explanation.Size = new Size(405, 38);
                explanation.Text = confirmation
                    ? "Transferpasswort festlegen (mindestens 12 Zeichen):"
                    : "Transferpasswort eingeben:";

                Label passwordLabel = new Label();
                passwordLabel.AutoSize = true;
                passwordLabel.Location = new Point(12, 58);
                passwordLabel.Text = "Passwort:";

                passwordBox = new TextBox();
                passwordBox.Location = new Point(125, 55);
                passwordBox.Size = new Size(292, 23);
                passwordBox.UseSystemPasswordChar = true;

                Controls.Add(explanation);
                Controls.Add(passwordLabel);
                Controls.Add(passwordBox);

                int buttonTop;

                if (confirmation)
                {
                    Label confirmationLabel = new Label();
                    confirmationLabel.AutoSize = true;
                    confirmationLabel.Location = new Point(12, 94);
                    confirmationLabel.Text = "Wiederholen:";

                    confirmationBox = new TextBox();
                    confirmationBox.Location = new Point(125, 91);
                    confirmationBox.Size = new Size(292, 23);
                    confirmationBox.UseSystemPasswordChar = true;

                    Controls.Add(confirmationLabel);
                    Controls.Add(confirmationBox);
                    buttonTop = 140;
                }
                else
                {
                    confirmationBox = null;
                    buttonTop = 95;
                }

                Button okButton = new Button();
                okButton.Text = "OK";
                okButton.Location = new Point(261, buttonTop);
                okButton.Size = new Size(75, 27);
                okButton.Click += OkButtonClick;

                Button cancelButton = new Button();
                cancelButton.Text = "Abbrechen";
                cancelButton.Location = new Point(342, buttonTop);
                cancelButton.Size = new Size(75, 27);
                cancelButton.DialogResult = DialogResult.Cancel;

                Controls.Add(okButton);
                Controls.Add(cancelButton);

                AcceptButton = okButton;
                CancelButton = cancelButton;
            }

            public string Password
            {
                get { return passwordBox.Text; }
            }

            private void OkButtonClick(object sender, EventArgs e)
            {
                if (String.IsNullOrEmpty(passwordBox.Text))
                {
                    MessageBox.Show(
                        this,
                        "Bitte ein Passwort eingeben.",
                        Text,
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    passwordBox.Focus();
                    return;
                }

                if (requireConfirmation)
                {
                    if (passwordBox.Text.Length < 12)
                    {
                        MessageBox.Show(
                            this,
                            "Das Transferpasswort muss mindestens 12 Zeichen lang sein.",
                            Text,
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                        passwordBox.Focus();
                        return;
                    }

                    if (!String.Equals(
                        passwordBox.Text,
                        confirmationBox.Text,
                        StringComparison.Ordinal))
                    {
                        MessageBox.Show(
                            this,
                            "Die eingegebenen Passwörter stimmen nicht überein.",
                            Text,
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                        confirmationBox.Focus();
                        return;
                    }
                }

                DialogResult = DialogResult.OK;
                Close();
            }

            public static bool Request(
                IWin32Window owner,
                string title,
                bool confirmation,
                out string password)
            {
                using (PasswordDialog dialog =
                    new PasswordDialog(title, confirmation))
                {
                    if (dialog.ShowDialog(owner) == DialogResult.OK)
                    {
                        password = dialog.Password;
                        return true;
                    }
                }

                password = null;
                return false;
            }
        }
    }
}