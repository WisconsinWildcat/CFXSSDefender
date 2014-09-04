/****** Object:  Table [dbo].[CrossScriptDefender]    Script Date: 9/4/2014 1:17:21 PM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[CrossScriptDefender](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[itemname] [varchar](50) NOT NULL,
	[itemtype] [varchar](50) NULL,
	[itemMaxLength] [int] NULL,
	[createdate] [smalldatetime] NULL,
	[samplevalues] [ntext] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO

SET ANSI_PADDING OFF
GO

ALTER TABLE [dbo].[CrossScriptDefender] ADD  CONSTRAINT [DF_CrossScriptDefender_createdate]  DEFAULT (getdate()) FOR [createdate]
GO

EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'Unique identifier for this table.' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'CrossScriptDefender', @level2type=N'COLUMN',@level2name=N'id'
GO

EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'Name of the parameter, url, or form variable defined.' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'CrossScriptDefender', @level2type=N'COLUMN',@level2name=N'itemname'
GO

EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'Type of variable; numeric, integer, text, string, list, ignore, fuseaction, boolean, and more.' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'CrossScriptDefender', @level2type=N'COLUMN',@level2name=N'itemtype'
GO

EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'Provided by the program to give us an idea what this variable is used for. Can also be used for comments.' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'CrossScriptDefender', @level2type=N'COLUMN',@level2name=N'samplevalues'
GO

EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'Largest possible size allowed for this variable. ' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'CrossScriptDefender', @level2type=N'COLUMN',@level2name=N'itemMaxLength'
GO

EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'Date this entry was created. Used primarily for sorting purposes.' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'CrossScriptDefender', @level2type=N'COLUMN',@level2name=N'createdate'
GO
