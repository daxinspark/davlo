CREATE TABLE [dbo].[Prescriptions] (
    [PrescriptionID] INT            IDENTITY (1, 1) NOT NULL,
    [PatientID]      INT            NULL,
    [DoctorID]       INT            NULL,
    [MedicationID]   INT            NULL,
    [DatePrescribed] DATE           NULL,
    [Dosage]         NVARCHAR (100) NULL,
    [DurationDays]   INT            NULL,
    PRIMARY KEY CLUSTERED ([PrescriptionID] ASC),
    FOREIGN KEY ([DoctorID]) REFERENCES [dbo].[Doctors] ([DoctorID]),
    FOREIGN KEY ([PatientID]) REFERENCES [dbo].[Patients] ([PatientID])
);
GO

