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
        private const int DefaultClipboardLifetimeSeconds = 30;
        private const int MinimumClipboardLifetimeSeconds = 5;
        private const int MaximumClipboardLifetimeSeconds = 600;
        private const string ConfigClipboardLifetimeSeconds =
            "Zentric.KeePassRecordExchange.ClipboardLifetimeSeconds";
        private const string ConfigClearClipboardAfterPaste =
            "Zentric.KeePassRecordExchange.ClearClipboardAfterPaste";
        private const int MaximumContainerCharacters = 140000000;
        private const long MaximumFileBytes = 100L * 1024L * 1024L;

        private static readonly byte[] AssociatedData =
            Encoding.UTF8.GetBytes("KeePassRecordExchange|1");

        private IPluginHost pluginHost;
        private Timer clipboardTimer;
        private string lastClipboardValue;
        private int clipboardLifetimeSeconds =
            DefaultClipboardLifetimeSeconds;
        private bool clearClipboardAfterPaste = true;

        public override bool Initialize(IPluginHost host)
        {
            if (host == null)
                return false;

            pluginHost = host;

            long configuredLifetime = pluginHost.CustomConfig.GetLong(
                ConfigClipboardLifetimeSeconds,
                DefaultClipboardLifetimeSeconds);

            clipboardLifetimeSeconds = ClampClipboardLifetime(
                configuredLifetime);

            clearClipboardAfterPaste = pluginHost.CustomConfig.GetBool(
                ConfigClearClipboardAfterPaste,
                true);

            clipboardTimer = new Timer();
            clipboardTimer.Interval = clipboardLifetimeSeconds * 1000;
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
                new ToolStripMenuItem("Copy Record(s) Encrypted");

            ToolStripMenuItem paste =
                new ToolStripMenuItem("Paste Record(s) Encrypted");

            ToolStripMenuItem exportFile =
                new ToolStripMenuItem("Export Record(s) to File");

            ToolStripMenuItem importFile =
                new ToolStripMenuItem("Import Record(s) from File");

            ToolStripMenuItem settings =
                new ToolStripMenuItem("Settings...");

            copy.Click += CopyEncrypted;
            paste.Click += PasteEncrypted;
            exportFile.Click += ExportEncryptedFile;
            importFile.Click += ImportEncryptedFile;
            settings.Click += OpenSettings;

            root.DropDownItems.Add(copy);
            root.DropDownItems.Add(paste);
            root.DropDownItems.Add(new ToolStripSeparator());
            root.DropDownItems.Add(exportFile);
            root.DropDownItems.Add(importFile);
            root.DropDownItems.Add(new ToolStripSeparator());
            root.DropDownItems.Add(settings);

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
                    "Copy Record(s) Encrypted",
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
                    " record(s) were copied to the clipboard in encrypted " +
                    "form.\r\n\r\n" +
                    "The clipboard will be cleared automatically after " +
                    clipboardLifetimeSeconds + " seconds.",
                    "Copy Record(s) Encrypted",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                ShowError("The record(s) could not be copied.", ex);
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
                        "The clipboard does not contain text.",
                        "Paste Record(s) Encrypted",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    return;
                }

                string container = Clipboard.GetText();
                ValidateContainerLength(container);

                string password;
                if (!PasswordDialog.Request(
                    pluginHost.MainWindow,
                    "Paste Record(s) Encrypted",
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
                if (clearClipboardAfterPaste)
                    ClearClipboardIfUnchanged(container);

                MessageBox.Show(
                    pluginHost.MainWindow,
                    count + " record(s) were imported successfully.",
                    "Paste Record(s) Encrypted",
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
                ShowError("The record(s) could not be pasted.", ex);
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
                    "Export Record(s) to File",
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
                    dialog.Title = "Export Encrypted KeePass Records";
                    dialog.Filter =
                        "KeePass Record Exchange (*.kprx)|*.kprx|All files (*.*)|*.*";
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
                        " record(s) were exported in encrypted form.",
                        "Export Record(s) to File",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                ShowError("The export file could not be created.", ex);
            }
        }

        private void ImportEncryptedFile(object sender, EventArgs e)
        {
            try
            {
                EnsureDatabaseOpen();

                using (OpenFileDialog dialog = new OpenFileDialog())
                {
                    dialog.Title = "Import Encrypted KeePass Records";
                    dialog.Filter =
                        "KeePass Record Exchange (*.kprx)|*.kprx|All files (*.*)|*.*";
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
                            "The file exceeds the maximum permitted size of 100 MB.");
                    }

                    string container = File.ReadAllText(
                        dialog.FileName,
                        Encoding.UTF8);

                    ValidateContainerLength(container);

                    string password;
                    if (!PasswordDialog.Request(
                        pluginHost.MainWindow,
                        "Import Record(s) from File",
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
                        count + " record(s) were imported successfully.",
                        "Import Record(s) from File",
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
                ShowError("The export file could not be imported.", ex);
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
                    "Please select at least one KeePass record.",
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

        private void OpenSettings(object sender, EventArgs e)
        {
            try
            {
                int newLifetime;
                bool newClearAfterPaste;

                if (!SettingsDialog.Request(
                    pluginHost.MainWindow,
                    clipboardLifetimeSeconds,
                    clearClipboardAfterPaste,
                    out newLifetime,
                    out newClearAfterPaste))
                {
                    return;
                }

                clipboardLifetimeSeconds = ClampClipboardLifetime(
                    newLifetime);
                clearClipboardAfterPaste = newClearAfterPaste;

                pluginHost.CustomConfig.SetLong(
                    ConfigClipboardLifetimeSeconds,
                    clipboardLifetimeSeconds);

                pluginHost.CustomConfig.SetBool(
                    ConfigClearClipboardAfterPaste,
                    clearClipboardAfterPaste);

                clipboardTimer.Interval =
                    clipboardLifetimeSeconds * 1000;

                // Restart an active countdown using the new interval.
                if (!String.IsNullOrEmpty(lastClipboardValue))
                {
                    clipboardTimer.Stop();
                    clipboardTimer.Start();
                }

                MessageBox.Show(
                    pluginHost.MainWindow,
                    "The settings have been saved.",
                    "Record Exchange Settings",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                ShowError("The settings could not be saved.", ex);
            }
        }

        private static int ClampClipboardLifetime(long value)
        {
            if (value < MinimumClipboardLifetimeSeconds)
                return MinimumClipboardLifetimeSeconds;

            if (value > MaximumClipboardLifetimeSeconds)
                return MaximumClipboardLifetimeSeconds;

            return (int)value;
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
                        "Invalid cryptographic parameters.");
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
                    "Invalid container encoding.", ex);
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
                    "The data is not a supported KeePass record container.");
            }
        }

        private static void ValidateRecords(List<RecordData> records)
        {
            if (records == null || records.Count == 0)
            {
                throw new InvalidOperationException(
                    "The container does not contain any records.");
            }

            if (records.Count > 10000)
            {
                throw new InvalidOperationException(
                    "The container contains too many records.");
            }

            foreach (RecordData record in records)
            {
                if (record == null || record.Fields == null)
                {
                    throw new InvalidOperationException(
                        "The container contains an invalid record.");
                }
            }
        }

        private static void ValidateContainerLength(string container)
        {
            if (String.IsNullOrWhiteSpace(container))
                throw new InvalidOperationException("The container is empty.");

            if (container.Length > MaximumContainerCharacters)
            {
                throw new InvalidOperationException(
                    "The container exceeds the maximum permitted size.");
            }
        }

        private void SetSensitiveClipboard(string value)
        {
            StopClipboardTimer();

            DataObject data = new DataObject();
            data.SetData(DataFormats.UnicodeText, value);

            // These Windows-defined formats request exclusion from
            // Clipboard History and Cloud Clipboard.
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
                // Another process can temporarily lock the clipboard.
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
                    "No KeePass database is open.");
            }
        }

        private int ImportRecords(List<RecordData> records)
        {
            ValidateRecords(records);

            PwGroup targetGroup = DetermineTargetGroup();
            if (targetGroup == null)
            {
                throw new InvalidOperationException(
                    "No target group could be determined.");
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
                "The password is incorrect or the container has been modified.",
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

        private sealed class SettingsDialog : Form
        {
            private readonly NumericUpDown clipboardLifetimeInput;
            private readonly CheckBox clearAfterPasteInput;

            private SettingsDialog(
                int clipboardLifetime,
                bool clearAfterPaste)
            {
                Text = "Record Exchange Settings";
                StartPosition = FormStartPosition.CenterParent;
                FormBorderStyle = FormBorderStyle.FixedDialog;
                MaximizeBox = false;
                MinimizeBox = false;
                ShowInTaskbar = false;
                ClientSize = new Size(470, 245);

                Label lifetimeLabel = new Label();
                lifetimeLabel.AutoSize = true;
                lifetimeLabel.Location = new Point(15, 23);
                lifetimeLabel.Text = "Clear clipboard after:";

                clipboardLifetimeInput = new NumericUpDown();
                clipboardLifetimeInput.Location = new Point(185, 20);
                clipboardLifetimeInput.Size = new Size(90, 23);
                clipboardLifetimeInput.Minimum =
                    MinimumClipboardLifetimeSeconds;
                clipboardLifetimeInput.Maximum =
                    MaximumClipboardLifetimeSeconds;
                clipboardLifetimeInput.Increment = 5;
                clipboardLifetimeInput.DecimalPlaces = 0;
                clipboardLifetimeInput.Value = ClampClipboardLifetime(
                    clipboardLifetime);

                Label secondsLabel = new Label();
                secondsLabel.AutoSize = true;
                secondsLabel.Location = new Point(283, 23);
                secondsLabel.Text = "seconds";

                clearAfterPasteInput = new CheckBox();
                clearAfterPasteInput.AutoSize = true;
                clearAfterPasteInput.Location = new Point(18, 65);
                clearAfterPasteInput.Text =
                    "Clear clipboard immediately after a successful paste";
                clearAfterPasteInput.Checked = clearAfterPaste;

                Label securityLabel = new Label();
                securityLabel.AutoSize = false;
                securityLabel.Location = new Point(18, 92);
                securityLabel.Size = new Size(435, 35);
                securityLabel.Text =
                    "Clipboard History and Cloud Clipboard exclusion always " +
                    "remain enabled.";

                Label attributionLabel = new Label();
                attributionLabel.AutoSize = false;
                attributionLabel.Location = new Point(18, 132);
                attributionLabel.Size = new Size(435, 43);
                attributionLabel.Text =
                    "Author: Chris Ditze-Stephan\r\n" +
                    "License: MIT - free to use, copy, modify and distribute";

                Button saveButton = new Button();
                saveButton.Text = "Save";
                saveButton.Location = new Point(302, 205);
                saveButton.Size = new Size(75, 27);
                saveButton.DialogResult = DialogResult.OK;

                Button cancelButton = new Button();
                cancelButton.Text = "Cancel";
                cancelButton.Location = new Point(383, 205);
                cancelButton.Size = new Size(75, 27);
                cancelButton.DialogResult = DialogResult.Cancel;

                Controls.Add(lifetimeLabel);
                Controls.Add(clipboardLifetimeInput);
                Controls.Add(secondsLabel);
                Controls.Add(clearAfterPasteInput);
                Controls.Add(securityLabel);
                Controls.Add(attributionLabel);
                Controls.Add(saveButton);
                Controls.Add(cancelButton);

                AcceptButton = saveButton;
                CancelButton = cancelButton;
            }

            private int ClipboardLifetime
            {
                get { return (int)clipboardLifetimeInput.Value; }
            }

            private bool ClearAfterPaste
            {
                get { return clearAfterPasteInput.Checked; }
            }

            public static bool Request(
                IWin32Window owner,
                int currentLifetime,
                bool currentClearAfterPaste,
                out int newLifetime,
                out bool newClearAfterPaste)
            {
                using (SettingsDialog dialog = new SettingsDialog(
                    currentLifetime,
                    currentClearAfterPaste))
                {
                    if (dialog.ShowDialog(owner) == DialogResult.OK)
                    {
                        newLifetime = dialog.ClipboardLifetime;
                        newClearAfterPaste = dialog.ClearAfterPaste;
                        return true;
                    }
                }

                newLifetime = currentLifetime;
                newClearAfterPaste = currentClearAfterPaste;
                return false;
            }
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
                    ? "Set a transfer password (at least 12 characters):"
                    : "Enter the transfer password:";

                Label passwordLabel = new Label();
                passwordLabel.AutoSize = true;
                passwordLabel.Location = new Point(12, 58);
                passwordLabel.Text = "Password:";

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
                    confirmationLabel.Text = "Confirm:";

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
                cancelButton.Text = "Cancel";
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
                        "Please enter a password.",
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
                            "The transfer password must contain at least 12 characters.",
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
                            "The passwords do not match.",
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
