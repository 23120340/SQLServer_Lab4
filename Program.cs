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

    public static string AdminPublicKey()
    {
        var table = Query("SP_SEL_ADMIN_PUBLICKEY");
        if (table.Rows.Count == 0)
            throw new InvalidOperationException("Chưa có tài khoản ADMIN trong hệ thống.");
        return table.Rows[0]["PUBKEY"].ToString()!;
    }
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

    public static void Clear()
    {
        Passwords.Clear();
        PrivateKeys.Clear();
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
            throw new InvalidOperationException($"Không tìm thấy private key của {manv}: {path}");
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
        Text = "SQLServer Lab4 - Đăng nhập";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(430, 300);
        StartPosition = FormStartPosition.CenterScreen;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(18), RowCount = 6, ColumnCount = 2 };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 95));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var i = 0; i < 4; i++)
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));

        AddRow(root, 0, "Server", _server);
        AddRow(root, 1, "Database", _database);
        AddRow(root, 2, "MANV", _manv);
        AddRow(root, 3, "Mật khẩu", _password);

        // Hàng nút chính: "Đăng nhập" trải hết chiều ngang.
        var login = new Button { Text = "Đăng nhập", Dock = DockStyle.Fill, Margin = new Padding(2, 8, 2, 4) };
        login.Click += (_, _) => Login();
        root.Controls.Add(login, 0, 4);
        root.SetColumnSpan(login, 2);

        // Hàng nút phụ: "Seed mẫu" và "Đăng ký" chia đôi đều nhau.
        var secondary = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0) };
        secondary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        secondary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var seed = new Button { Text = "Seed mẫu", Dock = DockStyle.Fill, Margin = new Padding(2, 2, 4, 2) };
        seed.Click += (_, _) => Seed();
        var register = new Button { Text = "Đăng ký", Dock = DockStyle.Fill, Margin = new Padding(4, 2, 2, 2) };
        register.Click += (_, _) => { ApplyConnection(); new RegisterForm().ShowDialog(this); };
        secondary.Controls.Add(seed, 0, 0);
        secondary.Controls.Add(register, 1, 0);
        root.Controls.Add(secondary, 0, 5);
        root.SetColumnSpan(secondary, 2);

        AcceptButton = login;   // nhấn Enter để đăng nhập
        Controls.Add(root);
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
                MessageBox.Show("Sai MANV hoặc mật khẩu.");
                return;
            }

            var privateKey = Crypto.LoadPrivateKey(_manv.Text.Trim(), _password.Text);
            PasswordCache.Remember(_manv.Text.Trim(), _password.Text, privateKey);
            var row = table.Rows[0];
            Hide();
            new MainForm(new Session((string)row["MANV"], (string)row["HOTEN"], (string)row["VAITRO"], _password.Text, privateKey)).ShowDialog();
            PasswordCache.Clear();
            Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Đăng nhập lỗi");
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

            SafeExec("SP_INS_LOP", Db.P("@MALOP", "L01"), Db.P("@TENLOP", "Lop CSDL K21"), Db.P("@MANV", "NV01"), Db.P("@MAHP", "CSDL"), Db.P("@MANV_LOGIN", "ADMIN"));
            SafeExec("SP_INS_LOP", Db.P("@MALOP", "L02"), Db.P("@TENLOP", "Lop ATBM K21"), Db.P("@MANV", "NV02"), Db.P("@MAHP", "ATBM"), Db.P("@MANV_LOGIN", "ADMIN"));
            SafeExec("SP_INS_SV", Db.P("@MASV", "SV001"), Db.P("@HOTEN", "Pham Van Sinh"), Db.P("@NGAYSINH", new DateTime(2003, 5, 10)), Db.P("@DIACHI", "TPHCM"), Db.P("@MALOP", "L01"), Db.P("@TENDN", "SV001"), Db.P("@MK", Crypto.Sha1("123")), Db.P("@MANV_LOGIN", "NV01"));
            SafeExec("SP_INS_SV", Db.P("@MASV", "SV002"), Db.P("@HOTEN", "Vo Thi Hoa"), Db.P("@NGAYSINH", new DateTime(2003, 8, 22)), Db.P("@DIACHI", "Dong Nai"), Db.P("@MALOP", "L01"), Db.P("@TENDN", "SV002"), Db.P("@MK", Crypto.Sha1("123")), Db.P("@MANV_LOGIN", "NV01"));
            SafeExec("SP_INS_SV", Db.P("@MASV", "SV003"), Db.P("@HOTEN", "Hoang Minh"), Db.P("@NGAYSINH", new DateTime(2003, 2, 14)), Db.P("@DIACHI", "Binh Duong"), Db.P("@MALOP", "L02"), Db.P("@TENDN", "SV003"), Db.P("@MK", Crypto.Sha1("123")), Db.P("@MANV_LOGIN", "NV02"));

            MessageBox.Show("Đã tạo dữ liệu mẫu. Admin: ADMIN/admin123. NV: NV01/abcd12, NV02/pass02, NV03/pass03.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Seed lỗi");
        }
    }

    private static void SeedEmployee(string manv, string hoten, string email, string salary, string tendn, string password, string role, string? adminManv)
    {
        if (Db.Query("SP_SEL_NHANVIEN_PUBLICKEY", Db.P("@MANV", manv)).Rows.Count > 0)
            return;

        var keyPair = Crypto.CreateKeyPair(password);
        Crypto.SavePrivateKey(manv, keyPair.EncryptedPrivateKey);
        PasswordCache.Remember(manv, password, Crypto.LoadPrivateKey(manv, password));

        // LUONG: mã hóa bằng public key của chính nhân viên (chỉ họ tự xem được).
        // LUONG_ADMIN: mã hóa bằng public key của admin (để admin luôn giải mã được).
        // Khi seed chính ADMIN thì chưa có admin trong DB, dùng luôn public key vừa tạo.
        var adminPub = role == "ADMIN" ? keyPair.PublicKey : Db.AdminPublicKey();
        SafeExec("SP_INS_PUBLIC_ENCRYPT_NHANVIEN",
            Db.P("@MANV", manv),
            Db.P("@HOTEN", hoten),
            Db.P("@EMAIL", email),
            Db.P("@LUONG", Crypto.EncryptText(keyPair.PublicKey, salary)),
            Db.P("@LUONG_ADMIN", Crypto.EncryptText(adminPub, salary)),
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
        Text = "Đăng ký nhân viên";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(560, 180);
        StartPosition = FormStartPosition.CenterParent;
        Padding = new Padding(14);

        var form = MainForm.FormGrid(("MANV", _manv), ("Họ tên", _hoten), ("Email", _email), ("Tên ĐN", _tendn), ("Mật khẩu", _password));
        var register = new Button { Text = "Tạo tài khoản", Dock = DockStyle.Bottom, Height = 38 };
        register.Click += (_, _) => Register();

        Controls.Add(form);       // FormGrid đã Dock=Top
        Controls.Add(register);   // ghim đáy, luôn hiển thị đủ
    }

    private void Register()
    {
        if (!MainForm.Require(("MANV", _manv.Text), ("Họ tên", _hoten.Text), ("Tên ĐN", _tendn.Text), ("Mật khẩu", _password.Text)))
            return;

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
            MessageBox.Show("Đã tạo tài khoản nhân viên. Admin có thể cập nhật lương sau.");
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Đăng ký lỗi");
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
    // ShowCheckBox: bỏ tick = "không đổi ngày sinh" (khi sửa) / "không nhập" (khi thêm).
    private readonly DateTimePicker _sNgaysinh = new() { Format = DateTimePickerFormat.Short, ShowCheckBox = true, Checked = false };
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
        var page = Page("Nhân viên");
        var form = FormGrid(("MANV", _eManv), ("Họ tên", _eHoten), ("Email", _eEmail), ("Lương", _eLuong), ("Tên ĐN", _eTendn), ("Mật khẩu", _eMk), ("Role", _eRole));
        var add = new Button { Text = "Thêm NV", Width = 110, Height = 30, Enabled = _session.IsAdmin };
        add.Click += (_, _) => AddEmployee();
        var salary = new Button { Text = "Cập nhật lương", Width = 130, Height = 30, Enabled = _session.IsAdmin };
        salary.Click += (_, _) => UpdateSalary();
        var reload = new Button { Text = "Tải lại", Width = 90, Height = 30 };
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
        var page = Page("Lớp học");
        var form = FormGrid(("Mã lớp", _lMalop), ("Tên lớp", _lTenlop), ("MANV", _lManv), ("MAHP", _lMahp));
        var buttons = Buttons(("Thêm lớp", AddClass), ("Sửa lớp", UpdateClass), ("Tải lại", LoadClasses));
        page.Controls.Add(_classes);
        page.Controls.Add(buttons);
        page.Controls.Add(form);
        return page;
    }

    private TabPage StudentTab()
    {
        var page = Page("Sinh viên");
        var form = FormGrid(("MASV", _sMasv), ("Họ tên", _sHoten), ("Ngày sinh", _sNgaysinh), ("Địa chỉ", _sDiachi), ("Mã lớp", _sMalop), ("Tên ĐN", _sTendn), ("Mật khẩu", _sMk));
        var buttons = Buttons(("Thêm SV", AddStudent), ("Sửa SV", UpdateStudent), ("Xóa SV", DeleteStudent), ("Tải lớp", LoadStudents), ("Xem tất cả SV", LoadAllStudents));
        page.Controls.Add(_students);
        page.Controls.Add(buttons);
        page.Controls.Add(form);
        return page;
    }

    private TabPage ScoreTab()
    {
        var page = Page("Bảng điểm");
        var form = FormGrid(("Mã lớp", _scoreMalop), ("MASV", _scoreMasv), ("MAHP", _scoreMahp), ("Điểm", _scoreDiem));
        var buttons = Buttons(("Tải điểm", LoadScores), ("Nhập điểm", SaveScore));
        page.Controls.Add(_scores);
        page.Controls.Add(buttons);
        page.Controls.Add(form);
        return page;
    }

    private void AddEmployee()
    {
        if (!_session.IsAdmin)
        {
            MessageBox.Show("Chỉ admin mới có quyền thêm nhân viên có lương.");
            return;
        }

        if (!Require(("MANV", _eManv.Text), ("Họ tên", _eHoten.Text), ("Lương", _eLuong.Text), ("Tên ĐN", _eTendn.Text), ("Mật khẩu", _eMk.Text)))
            return;

        try
        {
            var keyPair = Crypto.CreateKeyPair(_eMk.Text);
            Crypto.SavePrivateKey(_eManv.Text.Trim(), keyPair.EncryptedPrivateKey);
            PasswordCache.Remember(_eManv.Text.Trim(), _eMk.Text, Crypto.LoadPrivateKey(_eManv.Text.Trim(), _eMk.Text));
            var salary = _eLuong.Text.Trim();
            var encryptedSalary = Crypto.EncryptText(keyPair.PublicKey, salary);
            var encryptedForAdmin = Crypto.EncryptText(Db.AdminPublicKey(), salary);

            Db.Exec("SP_INS_PUBLIC_ENCRYPT_NHANVIEN",
                Db.P("@MANV", _eManv.Text.Trim()),
                Db.P("@HOTEN", _eHoten.Text.Trim()),
                Db.P("@EMAIL", _eEmail.Text.Trim()),
                Db.P("@LUONG", encryptedSalary),
                Db.P("@LUONG_ADMIN", encryptedForAdmin),
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
                MessageBox.Show("Không tìm thấy nhân viên.");
                return;
            }

            var pub = pubTable.Rows[0]["PUBKEY"].ToString()!;
            var salary = _eLuong.Text.Trim();
            Db.Exec("SP_UPD_NHANVIEN_LUONG",
                Db.P("@MANV", manv),
                Db.P("@LUONG", Crypto.EncryptText(pub, salary)),
                Db.P("@LUONG_ADMIN", Crypto.EncryptText(Db.AdminPublicKey(), salary)),
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
                string? plain = null;

                // Admin giải mã LUONG_ADMIN bằng private key của admin -> xem được lương mọi người.
                if (_session.IsAdmin && row["LUONG_ADMIN"] != DBNull.Value)
                    plain = Crypto.DecryptText(_session.PrivateKey, (byte[])row["LUONG_ADMIN"]);
                // Nhân viên thường chỉ giải mã được lương của chính mình bằng private key riêng.
                else if (row["LUONG"] != DBNull.Value && PasswordCache.TryGetPrivateKey(manv, out var privateKey))
                    plain = Crypto.DecryptText(privateKey, (byte[])row["LUONG"]);

                if (plain != null)
                    row["LUONG_GIAIMA"] = plain;
                else if (row["LUONG"] != DBNull.Value)
                    row["LUONG_GIAIMA"] = BitConverter.ToString((byte[])row["LUONG"]).Replace("-", "");
                else
                    row["LUONG_GIAIMA"] = "";
            }

            _employees.DataSource = table;
            HideBinaryColumns(_employees);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void AddClass()
    {
        if (!Require(("Mã lớp", _lMalop.Text), ("Tên lớp", _lTenlop.Text), ("MANV", _lManv.Text), ("MAHP", _lMahp.Text)))
            return;

        try
        {
            Db.Exec("SP_INS_LOP", Db.P("@MALOP", _lMalop.Text.Trim()), Db.P("@TENLOP", _lTenlop.Text.Trim()), Db.P("@MANV", _lManv.Text.Trim()), Db.P("@MAHP", EmptyToNull(_lMahp.Text)), Db.P("@MANV_LOGIN", _session.Manv));
            LoadClasses();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void UpdateClass()
    {
        if (!ConfirmBlanks(("Tên lớp", string.IsNullOrWhiteSpace(_lTenlop.Text)), ("MANV", string.IsNullOrWhiteSpace(_lManv.Text)), ("MAHP", string.IsNullOrWhiteSpace(_lMahp.Text))))
            return;

        try
        {
            Db.Exec("SP_UPD_LOP", Db.P("@MALOP", _lMalop.Text.Trim()), Db.P("@TENLOP", _lTenlop.Text.Trim()), Db.P("@MANV", EmptyToNull(_lManv.Text)), Db.P("@MAHP", EmptyToNull(_lMahp.Text)), Db.P("@MANV_LOGIN", _session.Manv));
            LoadClasses();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void LoadClasses()
    {
        try { _classes.DataSource = Db.Query("SP_SEL_LOP_ALL"); }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    // Trả về ngày khi người dùng có tick chọn, ngược lại NULL (không nhập / không đổi).
    private object? NgaySinhValue() => _sNgaysinh.Checked ? _sNgaysinh.Value.Date : null;

    private void AddStudent()
    {
        if (!Require(("MASV", _sMasv.Text), ("Họ tên", _sHoten.Text), ("Mã lớp", _sMalop.Text), ("Tên ĐN", _sTendn.Text), ("Mật khẩu", _sMk.Text)))
            return;

        try
        {
            Db.Exec("SP_INS_SV",
                Db.P("@MASV", _sMasv.Text.Trim()),
                Db.P("@HOTEN", _sHoten.Text.Trim()),
                Db.P("@NGAYSINH", NgaySinhValue()),
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
        if (!ConfirmBlanks(("Họ tên", string.IsNullOrWhiteSpace(_sHoten.Text)), ("Ngày sinh", !_sNgaysinh.Checked), ("Địa chỉ", string.IsNullOrWhiteSpace(_sDiachi.Text))))
            return;

        try
        {
            Db.Exec("SP_UPD_SV",
                Db.P("@MASV", _sMasv.Text.Trim()),
                Db.P("@HOTEN", _sHoten.Text.Trim()),
                Db.P("@NGAYSINH", NgaySinhValue()),
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

    private void LoadAllStudents()
    {
        // Admin xem toàn bộ SV; nhân viên thường chỉ thấy SV thuộc lớp mình phụ trách.
        try { _students.DataSource = Db.Query("SP_SEL_SV_ALL", Db.P("@MANV_LOGIN", _session.Manv)); }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void LoadScores()
    {
        if (!Require(("Mã lớp", _scoreMalop.Text), ("MAHP", _scoreMahp.Text)))
            return;

        try
        {
            var table = Db.Query("SP_SEL_BANGDIEM_ENCRYPT", Db.P("@MALOP", _scoreMalop.Text.Trim()), Db.P("@MAHP", _scoreMahp.Text.Trim()), Db.P("@MANV_LOGIN", _session.Manv));
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
        if (!Require(("Mã lớp", _scoreMalop.Text), ("MASV", _scoreMasv.Text), ("MAHP", _scoreMahp.Text), ("Điểm", _scoreDiem.Text)))
            return;

        try
        {
            var pub = Db.Query("SP_SEL_NHANVIEN_PUBLICKEY", Db.P("@MANV", _session.Manv)).Rows[0]["PUBKEY"].ToString()!;
            var cipher = Crypto.EncryptText(pub, _scoreDiem.Text.Trim());
            Db.Exec("SP_INS_BANGDIEM_ENCRYPT", Db.P("@MASV", _scoreMasv.Text.Trim()), Db.P("@MALOP", _scoreMalop.Text.Trim()), Db.P("@MAHP", _scoreMahp.Text.Trim()), Db.P("@DIEMTHI", cipher), Db.P("@MANV_LOGIN", _session.Manv));
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

    // Bố cục form dùng chung: 2 cặp [nhãn | ô nhập] trên mỗi hàng để ô nhập luôn đủ rộng,
    // không bị bóp khi tab có nhiều trường (vd tab Nhân viên 7 trường).
    internal static TableLayoutPanel FormGrid(params (string Label, Control Input)[] fields)
    {
        const int rowHeight = 30;
        var rows = (fields.Length + 1) / 2;
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            ColumnCount = 4,
            RowCount = rows,
            Height = rows * rowHeight + 10,
            Padding = new Padding(0, 0, 0, 8)
        };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 95));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 95));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        for (var r = 0; r < rows; r++)
            panel.RowStyles.Add(new RowStyle(SizeType.Absolute, rowHeight));

        for (var i = 0; i < fields.Length; i++)
        {
            var row = i / 2;
            var pair = (i % 2) * 2;
            fields[i].Input.Dock = DockStyle.Fill;
            fields[i].Input.Margin = new Padding(2, 3, 8, 3);
            panel.Controls.Add(new Label { Text = fields[i].Label, Anchor = AnchorStyles.Left, AutoSize = true, Margin = new Padding(2, 7, 2, 0) }, pair, row);
            panel.Controls.Add(fields[i].Input, pair + 1, row);
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

    // Kiểm tra các trường bắt buộc trước khi Thêm. Mật khẩu được hash ở client nên SP không
    // bắt được rỗng -> phải chặn tại đây. Trả về false nếu còn ô trống (đã báo cho người dùng).
    internal static bool Require(params (string Label, string Value)[] fields)
    {
        var missing = fields.Where(f => string.IsNullOrWhiteSpace(f.Value)).Select(f => f.Label).ToList();
        if (missing.Count == 0)
            return true;
        MessageBox.Show("Vui lòng nhập đầy đủ: " + string.Join(", ", missing), "Thiếu thông tin");
        return false;
    }

    // Khi sửa: nếu có ô để trống thì cảnh báo (vì có thể là cố ý xóa thông tin) và để người dùng
    // xác nhận. Trả về true nếu không có ô trống hoặc người dùng đồng ý tiếp tục.
    internal static bool ConfirmBlanks(params (string Label, bool IsBlank)[] fields)
    {
        var blanks = fields.Where(f => f.IsBlank).Select(f => f.Label).ToList();
        if (blanks.Count == 0)
            return true;
        return MessageBox.Show(
            "Các ô sau đang để trống và sẽ XÓA thông tin cũ: " + string.Join(", ", blanks) + "\n\nBạn có chắc muốn tiếp tục?",
            "Cảnh báo ô trống", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes;
    }

    private static void HideBinaryColumns(DataGridView grid)
    {
        foreach (DataGridViewColumn col in grid.Columns)
        {
            if (col.Name is "LUONG" or "LUONG_ADMIN" or "DIEMTHI" or "PUBKEY")
                col.Visible = false;
        }
    }
}