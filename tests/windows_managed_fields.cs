// Interactive Windows CI fixture. All values and commands are synthetic.
using System;
using System.Threading;
using Forms = System.Windows.Forms;
using Wpf = System.Windows;
using Controls = System.Windows.Controls;

class ManagedFields {
    static void Commands(Action<Action> invoke, Action<string> focus, Func<string, bool> matches, Action close) {
        var reader = new Thread(() => {
            Console.WriteLine("ready");
            string command;
            while ((command = Console.ReadLine()) != null) {
                if (command == "exit") break;
                invoke(() => {
                    if (command.StartsWith("verify")) Console.WriteLine(matches(command) ? "match" : "mismatch");
                    else {
                        focus(command);
                        Console.WriteLine("focused");
                    }
                });
            }
            invoke(close);
        });
        reader.IsBackground = true;
        reader.Start();
    }

    [STAThread]
    static void Main(string[] args) {
        if (args[0] == "winforms") {
            var window = new Forms.Form();
            var panel = new Forms.FlowLayoutPanel { Dock = Forms.DockStyle.Fill };
            window.Controls.Add(panel);
            var user = new Forms.TextBox();
            var password = new Forms.TextBox { UseSystemPasswordChar = true };
            var capture = new Forms.TextBox { ReadOnly = true, Text = "invented-capture" };
            panel.Controls.AddRange(new Forms.Control[] {user, password, capture});
            // A busy but responsive app: each change handler runs longer than
            // a probe may wait, but inside the write limit.
            EventHandler busy = (s, e) => Thread.Sleep(300);
            user.TextChanged += busy;
            password.TextChanged += busy;
            window.Shown += (s, e) => Commands(a => window.Invoke(a), name => {
                window.Activate();
                (name == "user" ? user : name == "password" ? password : capture).Focus();
            }, command => user.Text == "invented-user\U0001F600" && password.Text == "invented-password", window.Close);
            Forms.Application.Run(window);
        } else {
            var window = new Wpf.Window { Width = 400, Height = 200 };
            var panel = new Controls.StackPanel();
            var user = new Controls.TextBox();
            user.TextChanged += (sender, argsChanged) => {
                if (user.Text == "\u0628A\u030A") user.Text = "\u0628\u00C5";
            };
            var password = new Controls.PasswordBox();
            var capture = new Controls.TextBox { IsReadOnly = true, Text = "invented-capture" };
            panel.Children.Add(user);
            panel.Children.Add(password);
            panel.Children.Add(capture);
            window.Content = panel;
            window.ContentRendered += (s, e) => Commands(a => window.Dispatcher.Invoke(a), name => {
                window.Activate();
                (name == "password" ? (Wpf.UIElement) password : name == "user" ? user : capture).Focus();
            }, command => user.Text == (command == "verify-normalized" ? "\u0628\u00C5" : "invented-user\U0001F600") && password.Password == "invented-password", window.Close);
            new Wpf.Application().Run(window);
        }
    }
}
