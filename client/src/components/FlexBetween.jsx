/* This code is importing the `Box` component from the `@mui/material` library and the `styled`
function from the `@mui/system` library. */
import { Box } from "@mui/material";
import { styled } from "@mui/system";

const FlexBetween = styled(Box)({
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
});

export default FlexBetween;
