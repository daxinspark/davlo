CREATE TABLE [dbo].[PatientLabTests] (
    [PatientLabTestID] INT            IDENTITY (1, 1) NOT NULL,
    [PatientID]        INT            NULL,
    [LabTestID]        INT            NULL,
    [TestDate]         DATE           NULL,
    [Result]           NVARCHAR (250) NULL,
    PRIMARY KEY CLUSTERED ([PatientLabTestID] ASC),
    FOREIGN KEY ([LabTestID]) REFERENCES [dbo].[LabTests] ([LabTestID]),
    FOREIGN KEY ([PatientID]) REFERENCES [dbo].[Patients] ([PatientID])
);
GO

