CREATE TABLE [dbo].[Rooms] (
    [RoomID]       INT           IDENTITY (1, 1) NOT NULL,
    [DepartmentID] INT           NULL,
    [RoomNumber]   NVARCHAR (10) NULL,
    [Type]         NVARCHAR (50) NULL,
    [Capacity]     INT           NULL,
    PRIMARY KEY CLUSTERED ([RoomID] ASC),
    FOREIGN KEY ([DepartmentID]) REFERENCES [dbo].[Departments] ([DepartmentID])
);
GO

