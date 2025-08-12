CREATE TABLE [dbo].[MedicalDevices] (
    [DeviceID]     INT            IDENTITY (1, 1) NOT NULL,
    [Name]         NVARCHAR (100) NULL,
    [Manufacturer] NVARCHAR (100) NULL,
    [PurchaseDate] DATE           NULL,
    [DepartmentID] INT            NULL,
    [Status]       NVARCHAR (50)  NULL,
    PRIMARY KEY CLUSTERED ([DeviceID] ASC),
    FOREIGN KEY ([DepartmentID]) REFERENCES [dbo].[Departments] ([DepartmentID])
);
GO

