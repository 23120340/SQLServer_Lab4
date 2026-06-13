using System.Data;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;

namespace SQLServerLab4;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new LoginForm());
    }
}

internal static class Db
{
    public static string ConnectionString { get; set; } =
        "Server=localhost;Database=QLSVNhom;Trusted_Connection=True;TrustServerCertificate=True;Encrypt=True";

    public static DataTable Query(string procedure, params SqlParameter[] parameters)
    {
        using var connection = new SqlConnection(ConnectionString);
        using var command = new SqlCommand(procedure, connection) { CommandType = CommandType.StoredProcedure };
        command.Parameters.AddRange(parameters);
        using var adapter = new SqlDataAdapter(command);
        var table = new DataTable();
        adapter.Fill(table);
        return table;
    }

    public static void Exec(string procedure, params SqlParameter[] parameters)
    {
        using var connection = new SqlConnection(ConnectionString);
        using var command = new SqlCommand(procedure, connection) { CommandType = CommandType.StoredProcedure };
        command.Parameters.AddRange(parameters);
        connection.Open();
        command.ExecuteNonQuery();
    }

    public static SqlParameter P(string name, object? value) => new(name, value ?? DBNull.Value);
}

internal sealed record Session(string Manv, string Hoten, string Role, string Password, byte[] PrivateKey)
{
    public bool IsAdmin => Role.Equals("ADMIN", StringComparison.OrdinalIgnoreCase);
}

internal static class PasswordCache
{
    private static readonly Dictionary<string, string> Passwords = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, byte[]> PrivateKeys = new(StringComparer.OrdinalIgnoreCase);

    public static void Remember(string manv, string password, byte[] privateKey)
    {
        Passwords[manv] = password;
        PrivateKeys[manv] = privateKey;
    }

    public static bool TryGetPrivateKey(string manv, out byte[] privateKey)
    {
        if (PrivateKeys.TryGetValue(manv, out privateKey!))
            return true;

        if (Passwords.TryGetValue(manv, out var password) && Crypto.HasPrivateKey(manv))
        {
            privateKey = Crypto.LoadPrivateKey(manv, password);
            PrivateKeys[manv] = privateKey;
            return true;
        }

        privateKey = [];
        return false;
    }
}

internal static class Crypto
{
    private static readonly string KeyDir = Path.Combine(AppContext.BaseDirectory, "keys");

    public static byte[] Sha1(string text) => SHA1.HashData(Encoding.UTF8.GetBytes(text));

    public static (string PublicKey, byte[] EncryptedPrivateKey) CreateKeyPair(string password)
    {
        using var rsa = RSA.Create(2048);
        return (Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()), ProtectPrivateKey(rsa.ExportPkcs8PrivateKey(), password));
    }

    public static void SavePrivateKey(string manv, byte[] encryptedPrivateKey)
    {
        Directory.CreateDirectory(KeyDir);
        File.WriteAllBytes(KeyPath(manv), encryptedPrivateKey);
    }

    public static byte[] LoadPrivateKey(string manv, string password)
    {
        var path = KeyPath(manv);
        if (!File.Exists(path))
            throw new InvalidOperationException($"Khong tim thay private key cua {manv}: {path}");
        return UnprotectPrivateKey(File.ReadAllBytes(path), password);
    }

    public static bool HasPrivateKey(string manv) => File.Exists(KeyPath(manv));

    public static byte[] EncryptText(string publicKey, string plainText)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
        return rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.OaepSHA256);
    }

    public static string DecryptText(byte[] privateKey, byte[] cipher)
    {
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKey, out _);
        return Encoding.UTF8.GetString(rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256));
    }

    private static byte[] ProtectPrivateKey(byte[] privateKey, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, 150_000, HashAlgorithmName.SHA256, 32);
        var cipher = new byte[privateKey.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(key, 16))
            aes.Encrypt(nonce, privateKey, cipher, tag);
        return Combine(salt, nonce, tag, cipher);
    }

    private static byte[] UnprotectPrivateKey(byte[] payload, string password)
    {
        var salt = payload[..16];
        var nonce = payload[16..28];
        var tag = payload[28..44];
        var cipher = payload[44..];
        var plain = new byte[cipher.Length];
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, 150_000, HashAlgorithmName.SHA256, 32);
        using (var aes = new AesGcm(key, 16))
            aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    private static byte[] Combine(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        var offset = 0;
        foreach (var part in parts)
        {
            Buffer.BlockCopy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }
        return result;
    }

    private static string KeyPath(string manv) => Path.Combine(KeyDir, $"{manv}.private.bin");
}

internal sealed class LoginForm : Form
{
    private readonly TextBox _server = new() { Text = "localhost" };
    private readonly TextBox _database = new() { Text = "QLSVNhom" };
    private readonly TextBox _manv = new() { Text = "ADMIN" };
    private readonly TextBox _password = new() { Text = "admin123", UseSystemPasswordChar = true };

    public LoginForm()
    {
        Text = "SQLServer Lab4 - Dang nhap";
        Width = 470;
        Height = 310;
        StartPosition = FormStartPosition.CenterScreen;

        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(18), RowCount = 6, ColumnCount = 2 };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        AddRow(panel, 0, "Server", _server);
        AddRow(panel, 1, "Database", _database);
        AddRow(panel, 2, "MANV", _manv);
        AddRow(panel, 3, "Mat khau", _password);

        var login = new Button { Text = "Dang nhap", Dock = DockStyle.Fill, Height = 34 };
        login.Click += (_, _) => Login();
        var seed = new Button { Text = "Seed mau", Dock = DockStyle.Fill, Height = 34 };
        seed.Click += (_, _) => Seed();
        var register = new Button { Text = "Register", Dock = DockStyle.Fill, Height = 34 };
        register.Click += (_, _) => { ApplyConnection(); new RegisterForm().ShowDialog(this); };

        panel.Controls.Add(login, 0, 4);
        panel.Controls.Add(seed, 1, 4);
        panel.Controls.Add(register, 1, 5);
        Controls.Add(panel);
    }

    private static void AddRow(TableLayoutPanel panel, int row, string label, Control input)
    {
        input.Dock = DockStyle.Fill;
        panel.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row);
        panel.Controls.Add(input, 1, row);
    }

    private void ApplyConnection()
    {
        Db.ConnectionString = $"Server={_server.Text.Trim()};Database={_database.Text.Trim()};Trusted_Connection=True;TrustServerCertificate=True;Encrypt=True";
    }

    private void Login()
    {
        try
        {
            ApplyConnection();
            var table = Db.Query("SP_LOGIN_NHANVIEN", Db.P("@MANV", _manv.Text.Trim()), Db.P("@MK", Crypto.Sha1(_password.Text)));
            if (table.Rows.Count == 0)
            {
                MessageBox.Show("Sai MANV hoac mat khau.");
                return;
            }

            var privateKey = Crypto.LoadPrivateKey(_manv.Text.Trim(), _password.Text);
            PasswordCache.Remember(_manv.Text.Trim(), _password.Text, privateKey);
            var row = table.Rows[0];
            Hide();
            new MainForm(new Session((string)row["MANV"], (string)row["HOTEN"], (string)row["VAITRO"], _password.Text, privateKey)).ShowDialog();
            Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Dang nhap loi");
        }
    }

    private void Seed()
    {
        try
        {
            ApplyConnection();
            SeedEmployee("ADMIN", "Quan tri he thong", "admin@hcmus", "0", "ADMIN", "admin123", "ADMIN", null);
            SeedEmployee("NV01", "Nguyen Van A", "nva@hcmus", "3000000", "NVA", "abcd12", "NHANVIEN", "ADMIN");
            SeedEmployee("NV02", "Tran Thi B", "ttb@hcmus", "4500000", "TTB", "pass02", "NHANVIEN", "ADMIN");
            SeedEmployee("NV03", "Le Van C", "lvc@hcmus", "5200000", "LVC", "pass03", "NHANVIEN", "ADMIN");

            SafeExec("SP_INS_LOP", Db.P("@MALOP", "L01"), Db.P("@TENLOP", "Lop CSDL K21"), Db.P("@MANV", "NV01"), Db.P("@MAHP", "CSDL"));
            SafeExec("SP_INS_LOP", Db.P("@MALOP", "L02"), Db.P("@TENLOP", "Lop ATBM K21"), Db.P("@MANV", "NV02"), Db.P("@MAHP", "ATBM"));
            SafeExec("SP_INS_SV", Db.P("@MASV", "SV001"), Db.P("@HOTEN", "Pham Van Sinh"), Db.P("@NGAYSINH", new DateTime(2003, 5, 10)), Db.P("@DIACHI", "TPHCM"), Db.P("@MALOP", "L01"), Db.P("@TENDN", "SV001"), Db.P("@MK", Crypto.Sha1("123")), Db.P("@MANV_LOGIN", "NV01"));
            SafeExec("SP_INS_SV", Db.P("@MASV", "SV002"), Db.P("@HOTEN", "Vo Thi Hoa"), Db.P("@NGAYSINH", new DateTime(2003, 8, 22)), Db.P("@DIACHI", "Dong Nai"), Db.P("@MALOP", "L01"), Db.P("@TENDN", "SV002"), Db.P("@MK", Crypto.Sha1("123")), Db.P("@MANV_LOGIN", "NV01"));
            SafeExec("SP_INS_SV", Db.P("@MASV", "SV003"), Db.P("@HOTEN", "Hoang Minh"), Db.P("@NGAYSINH", new DateTime(2003, 2, 14)), Db.P("@DIACHI", "Binh Duong"), Db.P("@MALOP", "L02"), Db.P("@TENDN", "SV003"), Db.P("@MK", Crypto.Sha1("123")), Db.P("@MANV_LOGIN", "NV02"));

            MessageBox.Show("Da tao du lieu mau. Admin: ADMIN/admin123. NV: NV01/abcd12, NV02/pass02, NV03/pass03.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Seed loi");
        }
    }

    private static void SeedEmployee(string manv, string hoten, string email, string salary, string tendn, string password, string role, string? adminManv)
    {
        if (Db.Query("SP_SEL_NHANVIEN_PUBLICKEY", Db.P("@MANV", manv)).Rows.Count > 0)
            return;

        var keyPair = Crypto.CreateKeyPair(password);
        Crypto.SavePrivateKey(manv, keyPair.EncryptedPrivateKey);
        PasswordCache.Remember(manv, password, Crypto.LoadPrivateKey(manv, password));
        SafeExec("SP_INS_PUBLIC_ENCRYPT_NHANVIEN",
            Db.P("@MANV", manv),
            Db.P("@HOTEN", hoten),
            Db.P("@EMAIL", email),
            Db.P("@LUONG", Crypto.EncryptText(keyPair.PublicKey, salary)),
            Db.P("@TENDN", tendn),
            Db.P("@MK", Crypto.Sha1(password)),
            Db.P("@PUB", keyPair.PublicKey),
            Db.P("@VAITRO", role),
            Db.P("@MANV_LOGIN", adminManv));
    }

    private static void SafeExec(string procedure, params SqlParameter[] parameters)
    {
        try { Db.Exec(procedure, parameters); }
        catch (SqlException ex) when (ex.Number is 2627 or 2601) { }
    }
}

internal sealed class RegisterForm : Form
{
    private readonly TextBox _manv = new();
    private readonly TextBox _hoten = new();
    private readonly TextBox _email = new();
    private readonly TextBox _tendn = new();
    private readonly TextBox _password = new() { UseSystemPasswordChar = true };

    public RegisterForm()
    {
        Text = "Register nhan vien";
        Width = 430;
        Height = 260;
        StartPosition = FormStartPosition.CenterParent;
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(16), RowCount = 6, ColumnCount = 2 };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        AddRow(panel, 0, "MANV", _manv);
        AddRow(panel, 1, "Ho ten", _hoten);
        AddRow(panel, 2, "Email", _email);
        AddRow(panel, 3, "Ten DN", _tendn);
        AddRow(panel, 4, "Mat khau", _password);
        var register = new Button { Text = "Tao account", Dock = DockStyle.Fill };
        register.Click += (_, _) => Register();
        panel.Controls.Add(register, 1, 5);
        Controls.Add(panel);
    }

    private static void AddRow(TableLayoutPanel panel, int row, string label, Control input)
    {
        input.Dock = DockStyle.Fill;
        panel.Controls.Add(new Label { Text = label, Anchor = AnchorStyles.Left, AutoSize = true }, 0, row);
        panel.Controls.Add(input, 1, row);
    }

    private void Register()
    {
        try
        {
            var keyPair = Crypto.CreateKeyPair(_password.Text);
            Crypto.SavePrivateKey(_manv.Text.Trim(), keyPair.EncryptedPrivateKey);
            PasswordCache.Remember(_manv.Text.Trim(), _password.Text, Crypto.LoadPrivateKey(_manv.Text.Trim(), _password.Text));
            Db.Exec("SP_REGISTER_NHANVIEN",
                Db.P("@MANV", _manv.Text.Trim()),
                Db.P("@HOTEN", _hoten.Text.Trim()),
                Db.P("@EMAIL", _email.Text.Trim()),
                Db.P("@TENDN", _tendn.Text.Trim()),
                Db.P("@MK", Crypto.Sha1(_password.Text)),
                Db.P("@PUB", keyPair.PublicKey));
            MessageBox.Show("Da tao account nhan vien. Admin co the cap nhat luong sau.");
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Register loi");
        }
    }
}

internal sealed class MainForm : Form
{
    private readonly Session _session;
    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill };

    private readonly DataGridView _employees = Grid();
    private readonly DataGridView _classes = Grid();
    private readonly DataGridView _students = Grid();
    private readonly DataGridView _scores = Grid();

    private readonly TextBox _eManv = new();
    private readonly TextBox _eHoten = new();
    private readonly TextBox _eEmail = new();
    private readonly TextBox _eLuong = new();
    private readonly TextBox _eTendn = new();
    private readonly TextBox _eMk = new() { UseSystemPasswordChar = true };
    private readonly ComboBox _eRole = new() { DropDownStyle = ComboBoxStyle.DropDownList };

    private readonly TextBox _lMalop = new();
    private readonly TextBox _lTenlop = new();
    private readonly TextBox _lManv = new();
    private readonly TextBox _lMahp = new();

    private readonly TextBox _sMasv = new();
    private readonly TextBox _sHoten = new();
    private readonly DateTimePicker _sNgaysinh = new() { Format = DateTimePickerFormat.Short };
    private readonly TextBox _sDiachi = new();
    private readonly TextBox _sMalop = new() { Text = "L01" };
    private readonly TextBox _sTendn = new();
    private readonly TextBox _sMk = new() { Text = "123" };

    private readonly TextBox _scoreMalop = new() { Text = "L01" };
    private readonly TextBox _scoreMasv = new();
    private readonly TextBox _scoreMahp = new() { Text = "CSDL" };
    private readonly TextBox _scoreDiem = new();

    public MainForm(Session session)
    {
        _session = session;
        _eRole.Items.AddRange(["NHANVIEN", "ADMIN"]);
        _eRole.SelectedIndex = 0;

        Text = $"SQLServer Lab4 - {_session.Manv} - {_session.Hoten} ({_session.Role})";
        Width = 1120;
        Height = 720;
        StartPosition = FormStartPosition.CenterScreen;

        _tabs.TabPages.Add(EmployeeTab());
        _tabs.TabPages.Add(ClassTab());
        _tabs.TabPages.Add(StudentTab());
        _tabs.TabPages.Add(ScoreTab());
        Controls.Add(_tabs);

        LoadEmployees();
        LoadClasses();
    }

    private TabPage EmployeeTab()
    {
        var page = Page("Nhan vien");
        var form = FormGrid(("MANV", _eManv), ("Ho ten", _eHoten), ("Email", _eEmail), ("Luong", _eLuong), ("Ten DN", _eTendn), ("Mat khau", _eMk), ("Role", _eRole));
        var add = new Button { Text = "Them NV", Width = 110, Height = 30, Enabled = _session.IsAdmin };
        add.Click += (_, _) => AddEmployee();
        var salary = new Button { Text = "Cap nhat luong", Width = 130, Height = 30, Enabled = _session.IsAdmin };
        salary.Click += (_, _) => UpdateSalary();
        var reload = new Button { Text = "Tai lai", Width = 90, Height = 30 };
        reload.Click += (_, _) => LoadEmployees();
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 42 };
        buttons.Controls.Add(add);
        buttons.Controls.Add(salary);
        buttons.Controls.Add(reload);
        page.Controls.Add(_employees);
        page.Controls.Add(buttons);
        page.Controls.Add(form);
        return page;
    }

    private TabPage ClassTab()
    {
        var page = Page("Lop hoc");
        var form = FormGrid(("Ma lop", _lMalop), ("Ten lop", _lTenlop), ("MANV", _lManv), ("MAHP", _lMahp));
        var buttons = Buttons(("Them lop", AddClass), ("Sua lop", UpdateClass), ("Tai lai", LoadClasses));
        page.Controls.Add(_classes);
        page.Controls.Add(buttons);
        page.Controls.Add(form);
        return page;
    }

    private TabPage StudentTab()
    {
        var page = Page("Sinh vien");
        var form = FormGrid(("MASV", _sMasv), ("Ho ten", _sHoten), ("Ngay sinh", _sNgaysinh), ("Dia chi", _sDiachi), ("Ma lop", _sMalop), ("Ten DN", _sTendn), ("Mat khau", _sMk));
        var buttons = Buttons(("Them SV", AddStudent), ("Sua SV", UpdateStudent), ("Xoa SV", DeleteStudent), ("Tai lop", LoadStudents));
        page.Controls.Add(_students);
        page.Controls.Add(buttons);
        page.Controls.Add(form);
        return page;
    }

    private TabPage ScoreTab()
    {
        var page = Page("Bang diem");
        var form = FormGrid(("Ma lop", _scoreMalop), ("MASV", _scoreMasv), ("MAHP", _scoreMahp), ("Diem", _scoreDiem));
        var buttons = Buttons(("Tai diem", LoadScores), ("Nhap diem", SaveScore));
        page.Controls.Add(_scores);
        page.Controls.Add(buttons);
        page.Controls.Add(form);
        return page;
    }

    private void AddEmployee()
    {
        if (!_session.IsAdmin)
        {
            MessageBox.Show("Chi admin moi co quyen them nhan vien co luong.");
            return;
        }

        try
        {
            var keyPair = Crypto.CreateKeyPair(_eMk.Text);
            Crypto.SavePrivateKey(_eManv.Text.Trim(), keyPair.EncryptedPrivateKey);
            PasswordCache.Remember(_eManv.Text.Trim(), _eMk.Text, Crypto.LoadPrivateKey(_eManv.Text.Trim(), _eMk.Text));
            var encryptedSalary = Crypto.EncryptText(keyPair.PublicKey, _eLuong.Text.Trim());

            Db.Exec("SP_INS_PUBLIC_ENCRYPT_NHANVIEN",
                Db.P("@MANV", _eManv.Text.Trim()),
                Db.P("@HOTEN", _eHoten.Text.Trim()),
                Db.P("@EMAIL", _eEmail.Text.Trim()),
                Db.P("@LUONG", encryptedSalary),
                Db.P("@TENDN", _eTendn.Text.Trim()),
                Db.P("@MK", Crypto.Sha1(_eMk.Text)),
                Db.P("@PUB", keyPair.PublicKey),
                Db.P("@VAITRO", _eRole.SelectedItem?.ToString() ?? "NHANVIEN"),
                Db.P("@MANV_LOGIN", _session.Manv));
            LoadEmployees();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void UpdateSalary()
    {
        if (!_session.IsAdmin)
            return;

        try
        {
            var manv = _eManv.Text.Trim();
            var pubTable = Db.Query("SP_SEL_NHANVIEN_PUBLICKEY", Db.P("@MANV", manv));
            if (pubTable.Rows.Count == 0)
            {
                MessageBox.Show("Khong tim thay nhan vien.");
                return;
            }

            var pub = pubTable.Rows[0]["PUBKEY"].ToString()!;
            Db.Exec("SP_UPD_NHANVIEN_LUONG",
                Db.P("@MANV", manv),
                Db.P("@LUONG", Crypto.EncryptText(pub, _eLuong.Text.Trim())),
                Db.P("@MANV_LOGIN", _session.Manv));
            LoadEmployees();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void LoadEmployees()
    {
        try
        {
            var table = Db.Query("SP_SEL_NHANVIEN_ALL");
            if (!table.Columns.Contains("LUONG_GIAIMA"))
                table.Columns.Add("LUONG_GIAIMA", typeof(string));

            foreach (DataRow row in table.Rows)
            {
                var manv = (string)row["MANV"];
                if (row["LUONG"] != DBNull.Value && PasswordCache.TryGetPrivateKey(manv, out var privateKey))
                    row["LUONG_GIAIMA"] = Crypto.DecryptText(privateKey, (byte[])row["LUONG"]);
                else
                    row["LUONG_GIAIMA"] = "(chua co password/private key trong cache)";
            }

            _employees.DataSource = table;
            HideBinaryColumns(_employees);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void AddClass()
    {
        try
        {
            Db.Exec("SP_INS_LOP", Db.P("@MALOP", _lMalop.Text.Trim()), Db.P("@TENLOP", _lTenlop.Text.Trim()), Db.P("@MANV", _lManv.Text.Trim()), Db.P("@MAHP", EmptyToNull(_lMahp.Text)));
            LoadClasses();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void UpdateClass()
    {
        try
        {
            Db.Exec("SP_UPD_LOP", Db.P("@MALOP", _lMalop.Text.Trim()), Db.P("@TENLOP", _lTenlop.Text.Trim()), Db.P("@MANV", _lManv.Text.Trim()), Db.P("@MAHP", EmptyToNull(_lMahp.Text)), Db.P("@MANV_LOGIN", _session.Manv));
            LoadClasses();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void LoadClasses()
    {
        try { _classes.DataSource = Db.Query("SP_SEL_LOP_ALL"); }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void AddStudent()
    {
        try
        {
            Db.Exec("SP_INS_SV",
                Db.P("@MASV", _sMasv.Text.Trim()),
                Db.P("@HOTEN", _sHoten.Text.Trim()),
                Db.P("@NGAYSINH", _sNgaysinh.Value.Date),
                Db.P("@DIACHI", _sDiachi.Text.Trim()),
                Db.P("@MALOP", _sMalop.Text.Trim()),
                Db.P("@TENDN", _sTendn.Text.Trim()),
                Db.P("@MK", Crypto.Sha1(_sMk.Text)),
                Db.P("@MANV_LOGIN", _session.Manv));
            LoadStudents();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void UpdateStudent()
    {
        try
        {
            Db.Exec("SP_UPD_SV",
                Db.P("@MASV", _sMasv.Text.Trim()),
                Db.P("@HOTEN", _sHoten.Text.Trim()),
                Db.P("@NGAYSINH", _sNgaysinh.Value.Date),
                Db.P("@DIACHI", _sDiachi.Text.Trim()),
                Db.P("@MANV_LOGIN", _session.Manv));
            LoadStudents();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void DeleteStudent()
    {
        try
        {
            Db.Exec("SP_DEL_SV",
                Db.P("@MASV", _sMasv.Text.Trim()),
                Db.P("@HOTEN", _sHoten.Text.Trim()),
                Db.P("@NGAYSINH", _sNgaysinh.Value.Date),
                Db.P("@DIACHI", _sDiachi.Text.Trim()),
                Db.P("@MANV_LOGIN", _session.Manv));
            LoadStudents();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void LoadStudents()
    {
        try { _students.DataSource = Db.Query("SP_SEL_SV_BY_LOP", Db.P("@MALOP", _sMalop.Text.Trim())); }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void LoadScores()
    {
        try
        {
            var table = Db.Query("SP_SEL_BANGDIEM_ENCRYPT", Db.P("@MALOP", _scoreMalop.Text.Trim()), Db.P("@MANV_LOGIN", _session.Manv));
            if (!table.Columns.Contains("DIEM_GIAIMA"))
                table.Columns.Add("DIEM_GIAIMA", typeof(string));

            foreach (DataRow row in table.Rows)
            {
                if (row["DIEMTHI"] != DBNull.Value && row["MANV_NHAP"] != DBNull.Value && PasswordCache.TryGetPrivateKey((string)row["MANV_NHAP"], out var privateKey))
                    row["DIEM_GIAIMA"] = Crypto.DecryptText(privateKey, (byte[])row["DIEMTHI"]);
                else
                    row["DIEM_GIAIMA"] = "";
            }

            _scores.DataSource = table;
            HideBinaryColumns(_scores);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void SaveScore()
    {
        try
        {
            var pub = Db.Query("SP_SEL_NHANVIEN_PUBLICKEY", Db.P("@MANV", _session.Manv)).Rows[0]["PUBKEY"].ToString()!;
            var cipher = Crypto.EncryptText(pub, _scoreDiem.Text.Trim());
            Db.Exec("SP_INS_BANGDIEM_ENCRYPT", Db.P("@MASV", _scoreMasv.Text.Trim()), Db.P("@MAHP", _scoreMahp.Text.Trim()), Db.P("@DIEMTHI", cipher), Db.P("@MANV_LOGIN", _session.Manv));
            LoadScores();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private static TabPage Page(string title) => new(title) { Padding = new Padding(10) };

    private static DataGridView Grid() => new()
    {
        Dock = DockStyle.Fill,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        AllowUserToAddRows = false,
        ReadOnly = true,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect
    };

    private static TableLayoutPanel FormGrid(params (string Label, Control Input)[] fields)
    {
        var panel = new TableLayoutPanel { Dock = DockStyle.Top, Height = 90, ColumnCount = fields.Length, RowCount = 2, Padding = new Padding(0, 0, 0, 6) };
        for (var i = 0; i < fields.Length; i++)
        {
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / fields.Length));
            fields[i].Input.Dock = DockStyle.Fill;
            panel.Controls.Add(new Label { Text = fields[i].Label, Dock = DockStyle.Fill }, i, 0);
            panel.Controls.Add(fields[i].Input, i, 1);
        }
        return panel;
    }

    private static FlowLayoutPanel Buttons(params (string Text, Action Action)[] buttons)
    {
        var panel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 42 };
        foreach (var item in buttons)
        {
            var button = new Button { Text = item.Text, Width = 110, Height = 30 };
            button.Click += (_, _) => item.Action();
            panel.Controls.Add(button);
        }
        return panel;
    }

    private static object? EmptyToNull(string text) => string.IsNullOrWhiteSpace(text) ? null : text.Trim();

    private static void HideBinaryColumns(DataGridView grid)
    {
        foreach (DataGridViewColumn col in grid.Columns)
        {
            if (col.Name is "LUONG" or "DIEMTHI" or "PUBKEY")
                col.Visible = false;
        }
    }
}
