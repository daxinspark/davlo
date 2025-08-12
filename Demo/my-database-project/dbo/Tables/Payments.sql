CREATE TABLE [dbo].[Payments] (
    [PaymentID]     INT             IDENTITY (1, 1) NOT NULL,
    [InvoiceID]     INT             NULL,
    [PaymentDate]   DATE            NULL,
    [AmountPaid]    DECIMAL (10, 2) NULL,
    [PaymentMethod] NVARCHAR (50)   NULL,
    PRIMARY KEY CLUSTERED ([PaymentID] ASC),
    FOREIGN KEY ([InvoiceID]) REFERENCES [dbo].[Invoices] ([InvoiceID])
);
GO

