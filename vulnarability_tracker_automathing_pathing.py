import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import subprocess

class VulnerabilityTrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vulnerability Tracker")
        self.root.geometry("1920x1080")  # Adjusted size to fit 1920x1080 resolution

        self.schedule_data = []  
        self.patch_data = []  

        self.create_widgets()
        self.load_saved_data()  

    def create_widgets(self):
        self.label = tk.Label(self.root, text="Schedule Vulnerability Scans and Track Patching Activities", font=("Helvetica", 16))
        self.label.grid(row=0, column=0, columnspan=4, padx=10, pady=10, sticky="w")

        # Entry fields for vulnerability details, IP address, date, application, and port
        self.vulnerability_label = tk.Label(self.root, text="Enter Vulnerability Details:")
        self.vulnerability_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.vulnerability_entry = tk.Entry(self.root, width=50)
        self.vulnerability_entry.grid(row=1, column=1, padx=5, pady=5)

        # Other entry fields...

        # Buttons to schedule scan, track patching, edit schedule ID, and open tables
        self.schedule_button = tk.Button(self.root, text="Schedule Scan", command=self.schedule_scan)
        self.schedule_button.grid(row=11, column=0, padx=5, pady=5)

        self.patch_button = tk.Button(self.root, text="Track Patching", command=self.track_patching)
        self.patch_button.grid(row=11, column=1, padx=5, pady=5)

        self.automate_patching_button = tk.Button(self.root, text="Automate Patching", command=self.automate_patching)
        self.automate_patching_button.grid(row=11, column=2, padx=5, pady=5)

        self.edit_schedule_id_button = tk.Button(self.root, text="Edit Schedule ID", command=self.edit_schedule_id)
        self.edit_schedule_id_button.grid(row=11, column=3, padx=5, pady=5)

        self.open_schedule_button = tk.Button(self.root, text="Open Scheduled Scans", command=self.open_schedule_table)
        self.open_schedule_button.grid(row=12, column=0, padx=5, pady=5)

        self.open_patch_button = tk.Button(self.root, text="Open Patching Activities", command=self.open_patch_table)
        self.open_patch_button.grid(row=12, column=1, padx=5, pady=5)

        self.delete_row_button = tk.Button(self.root, text="Delete Row", command=self.delete_row)
        self.delete_row_button.grid(row=12, column=2, padx=5, pady=5)

        self.email_var = tk.BooleanVar()
        self.email_checkbox = tk.Checkbutton(self.root, text="Send Email Notification", variable=self.email_var)
        self.email_checkbox.grid(row=13, column=0, columnspan=4, padx=5, pady=5, sticky="w")

        # Create the table headers
        self.tree = ttk.Treeview(self.root, columns=("ID", "Vulnerability Details", "IP Address", "Scan Date", "Scan Time", "Estimated Patch Date", "Estimated Patch Time", "Application", "Port", "Comment", "Schedule ID"), selectmode="extended")
        # Treeview headers...
        self.tree.grid(row=14, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")

        self.root.grid_rowconfigure(14, weight=1)
        self.root.grid_columnconfigure(3, weight=1)

    def schedule_scan(self):
        vulnerability_details = self.vulnerability_entry.get()
        ip_address = self.ip_entry.get()
        scan_date = self.date_entry.get()
        scan_time = self.time_entry.get()
        patch_date = self.patch_date_entry.get()
        patch_time = self.patch_time_entry.get()
        application = self.app_entry.get()
        port = self.port_entry.get()
        comment = self.comment_entry.get()

        if vulnerability_details and ip_address and scan_date and scan_time:
            if application and port:
                scan_details = f"{vulnerability_details}\t{ip_address}\t{scan_date}\t{scan_time}\t{patch_date}\t{patch_time}\t{application}\t{port}\t{comment}"
            else:
                scan_details = f"{vulnerability_details}\t{ip_address}\t{scan_date}\t{scan_time}\t{patch_date}\t{patch_time}\t{comment}"

            scan_id = len(self.schedule_data) + 1  
            self.schedule_data.append((scan_id, vulnerability_details, ip_address, scan_date, scan_time, patch_date, patch_time, application, port, comment))
            self.tree.insert("", "end", values=(scan_id, vulnerability_details, ip_address, scan_date, scan_time, patch_date, patch_time, application, port, comment, ""))
            messagebox.showinfo("Success", "Vulnerability scan scheduled successfully!")
            self.save_data()

            if self.email_var.get():
                recipient_email = simpledialog.askstring("Recipient's Email", "Enter recipient's email address:")
                if recipient_email:
                    self.send_email_notification(recipient_email, scan_details)
        else:
            messagebox.showerror("Error", "Please enter all required details.")

    def track_patching(self):
        vulnerability_details = self.vulnerability_entry.get()
        ip_address = self.ip_entry.get()
        patch_date = self.date_entry.get()
        patch_time = self.time_entry.get()
        estimated_patch_date = self.patch_date_entry.get()
        estimated_patch_time = self.patch_time_entry.get()
        application = self.app_entry.get()
        port = self.port_entry.get()
        comment = self.comment_entry.get()
        schedule_id = self.schedule_id_entry.get()

        if vulnerability_details and ip_address and patch_date and patch_time:
            if application and port:
                patch_details = f"{vulnerability_details}\t{ip_address}\t{patch_date}\t{patch_time}\t{estimated_patch_date}\t{estimated_patch_time}\t{application}\t{port}\t{comment}\t{schedule_id}"
            else:
                patch_details = f"{vulnerability_details}\t{ip_address}\t{patch_date}\t{patch_time}\t{estimated_patch_date}\t{estimated_patch_time}\t{comment}\t{schedule_id}"

            patch_id = len(self.patch_data) + 1  
            self.patch_data.append((patch_id, vulnerability_details, ip_address, patch_date, patch_time, estimated_patch_date, estimated_patch_time, application, port, comment, schedule_id))
            self.tree.insert("", "end", values=(patch_id, vulnerability_details, ip_address, patch_date, patch_time, estimated_patch_date, estimated_patch_time, application, port, comment, schedule_id))
            messagebox.showinfo("Success", "Patching activity tracked successfully!")
            self.save_data()

            if self.email_var.get():
                recipient_email = simpledialog.askstring("Recipient's Email", "Enter recipient's email address:")
                if recipient_email:
                    self.send_email_notification(recipient_email, patch_details)
        else:
            messagebox.showerror("Error", "Please enter all required details.")

    def edit_schedule_id(self):
        new_schedule_id = self.schedule_id_entry.get()
        selected_items = self.tree.selection()
        if selected_items:
            for item in selected_items:
                for data in self.patch_data:
                    if data[0] == int(self.tree.item(item, "values")[0]):  
                        data_index = self.patch_data.index(data)
                        self.patch_data[data_index] = (data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], new_schedule_id)
                self.save_data()
        else:
            messagebox.showerror("Error", "Please select a row to edit the schedule ID.")

    def delete_row(self):
        password = simpledialog.askstring("Delete Row", "Enter password to delete row:")
        if password == "1234":
            selected_items = self.tree.selection()
            if selected_items:
                for item in selected_items:
                    item_id = self.tree.item(item, "values")[0]
                    for i, data in enumerate(self.schedule_data):
                        if data[0] == item_id:
                            del self.schedule_data[i]
                            break
                    for i, data in enumerate(self.patch_data):
                        if data[0] == item_id:
                            del self.patch_data[i]
                            break
                    self.tree.delete(item)
                self.save_data()
            else:
                messagebox.showerror("Error", "Please select a row to delete.")
        else:
            messagebox.showerror("Error", "Incorrect password.")

    def open_schedule_table(self):
        self.open_table("Scheduled Scans", self.schedule_data)

    def open_patch_table(self):
        self.open_table("Patching Activities", self.patch_data)

    def open_table(self, title, data):
        if data:
            top = tk.Toplevel()
            top.title(title)

            tree = ttk.Treeview(top, columns=("ID", "Vulnerability Details", "IP Address", "Scan Date", "Scan Time", "Estimated Patch Date", "Estimated Patch Time", "Application", "Port", "Comment", "Schedule ID"), selectmode="extended")
            tree.heading("#0", text="ID")
            tree.heading("ID", text="ID")
            tree.heading("Vulnerability Details", text="Vulnerability Details")
            tree.heading("IP Address", text="IP Address")
            tree.heading("Scan Date", text="Scan Date")
            tree.heading("Scan Time", text="Scan Time")
            tree.heading("Estimated Patch Date", text="Estimated Patch Date")
            tree.heading("Estimated Patch Time", text="Estimated Patch Time")
            tree.heading("Application", text="Application")
            tree.heading("Port", text="Port")
            tree.heading("Comment", text="Comment")
            tree.heading("Schedule ID", text="Schedule ID")
            for item in data:
                tree.insert("", "end", values=item)
            tree.pack(fill="both", expand=True)
        else:
            messagebox.showinfo("Info", "No data available")

    def send_email_notification(self, recipient_email, scan_details):
        from_address = simpledialog.askstring("Your Email", "Enter your email address:")
        password = simpledialog.askstring("Your Email Password", "Enter your email password:", show='*')

        smtp_server = "smtp.example.com"
        smtp_port = 587

        message = MIMEMultipart()
        message["From"] = from_address
        message["To"] = recipient_email
        message["Subject"] = "Vulnerability Scan Notification"

        body = f"A vulnerability scan was scheduled with the following details:\n\n{scan_details}"
        message.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(from_address, password)
                server.send_message(message)
            print("Email notification sent successfully")
        except Exception as e:
            print(f"Error sending email: {e}")

    def load_saved_data(self):
        try:
            with open("schedule_data.json", "r") as file:
                self.schedule_data = json.load(file)
        except FileNotFoundError:
            pass

        try:
            with open("patch_data.json", "r") as file:
                self.patch_data = json.load(file)
        except FileNotFoundError:
            pass

    def save_data(self):
        with open("schedule_data.json", "w") as file:
            json.dump(self.schedule_data, file, indent=4)

        with open("patch_data.json", "w") as file:
            json.dump(self.patch_data, file, indent=4)

    def automate_patching(self):
        for patch_data in self.patch_data:
            vulnerability_details, ip_address, _, _, _, _, application, _, _, _, _ = patch_data
            if self.is_patching_needed(vulnerability_details, ip_address, application):
                self.execute_patch_command(ip_address, application)
                self.update_patching_status(patch_data)
                messagebox.showinfo("Patching", f"Patching for {vulnerability_details} on {ip_address} completed successfully.")

    def is_patching_needed(self, vulnerability_details, ip_address, application):
        return True

    def execute_patch_command(self, ip_address, application):
        subprocess.run(["ssh", "user@{}".format(ip_address), "apt-get update && apt-get upgrade -y"])

    def update_patching_status(self, patch_data):
        pass

def main():
    root = tk.Tk()
    app = VulnerabilityTrackerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
