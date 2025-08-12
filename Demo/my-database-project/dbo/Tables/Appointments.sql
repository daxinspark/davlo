CREATE TABLE [dbo].[Appointments] (
    [AppointmentID]       INT            IDENTITY (1, 1) NOT NULL,
    [PatientID]           INT            NULL,
    [DoctorID]            INT            NULL,
    [AppointmentDateTime] DATETIME       NULL,
    [Reason]              NVARCHAR (250) NULL,
    [Status]              NVARCHAR (50)  NULL,
    PRIMARY KEY CLUSTERED ([AppointmentID] ASC),
    FOREIGN KEY ([DoctorID]) REFERENCES [dbo].[Doctors] ([DoctorID]),
    FOREIGN KEY ([PatientID]) REFERENCES [dbo].[Patients] ([PatientID])
);
GO

