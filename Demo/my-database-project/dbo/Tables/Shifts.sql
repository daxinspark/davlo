CREATE TABLE [dbo].[Shifts] (
    [ShiftID]   INT      IDENTITY (1, 1) NOT NULL,
    [StaffID]   INT      NULL,
    [ShiftDate] DATE     NULL,
    [StartTime] TIME (7) NULL,
    [EndTime]   TIME (7) NULL,
    PRIMARY KEY CLUSTERED ([ShiftID] ASC),
    FOREIGN KEY ([StaffID]) REFERENCES [dbo].[StaffMembers] ([StaffID])
);
GO

