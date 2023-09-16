/* This code is importing the `Box` component from the `@mui/material` library and the `styled`
function from the `@mui/system` library. */
import { Box } from "@mui/material";
import { styled } from "@mui/system";

const WidgetWrapper = styled(Box)(({ theme }) => ({
    padding: "1.5rem 1.5rem 0.75rem 1.5rem",
    backgroundColor: theme.palette.background.alt,
    borderRadius: "0.75rem",
}));

export default WidgetWrapper;