CREATE TABLE [dbo].[Invoices] (
    [InvoiceID]   INT             IDENTITY (1, 1) NOT NULL,
    [PatientID]   INT             NULL,
    [InvoiceDate] DATE            NULL,
    [TotalAmount] DECIMAL (10, 2) NULL,
    [Paid]        BIT             NULL,
    PRIMARY KEY CLUSTERED ([InvoiceID] ASC),
    FOREIGN KEY ([PatientID]) REFERENCES [dbo].[Patients] ([PatientID])
);
GO

