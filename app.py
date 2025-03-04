#!/usr/bin/env python3
"""
Code Abbreviator using LibCST

This script uses LibCST to parse a Python file and abbreviate nested code blocks
beyond a specified depth, replacing them with ellipsis comments and pass statements.
Sections are only abbreviated if doing so actually reduces the character count.

Usage:
    python code_abbreviator.py [input_file] [--depth=N] [--debug]

Args:
    input_file: Path to the Python file to abbreviate (default: this script)
    --depth=N: Maximum nesting depth to preserve (default: 2)
    --debug: Enable debug output
"""

import argparse
import os
import sys
from typing import Dict, List, Optional, Set, Tuple, Union

import libcst as cst
from libcst.metadata import ParentNodeProvider, PositionProvider


class DebugInfo:
    """Class to collect debug information during transformation."""
    
    def __init__(self, enabled: bool = False):
        """
        Initialize debug info collector.
        
        Args:
            enabled: Whether debug mode is enabled
        """
        self.enabled = enabled
        self.nodes_considered = 0
        self.nodes_abbreviated = 0
        self.nodes_skipped = 0  # Nodes that weren't abbreviated due to no size reduction
        self.abbreviated_nodes = []
        self.skipped_nodes = []  # Nodes that weren't abbreviated
        self.max_depth_reached = 0
        self.depth_counts = {}
        self.chars_saved = 0  # Track total characters saved
    
    def consider_node(self, node: cst.CSTNode, depth: int) -> None:
        """
        Record that a node was considered for abbreviation.
        
        Args:
            node: The node being considered
            depth: Current nesting depth
        """
        if not self.enabled:
            return
            
        self.nodes_considered += 1
        self.max_depth_reached = max(self.max_depth_reached, depth)
        
        # Count nodes at each depth
        if depth not in self.depth_counts:
            self.depth_counts[depth] = 0
        self.depth_counts[depth] += 1
    
    def abbreviate_node(self, node: cst.CSTNode, depth: int, chars_saved: int) -> None:
        """
        Record that a node was abbreviated.
        
        Args:
            node: The node being abbreviated
            depth: Current nesting depth
            chars_saved: Number of characters saved by abbreviation
        """
        if not self.enabled:
            return
            
        self.nodes_abbreviated += 1
        self.abbreviated_nodes.append((node.__class__.__name__, depth, chars_saved))
        self.chars_saved += chars_saved
    
    def skip_node(self, node: cst.CSTNode, depth: int, reason: str) -> None:
        """
        Record that a node was not abbreviated.
        
        Args:
            node: The node that wasn't abbreviated
            depth: Current nesting depth
            reason: Reason for not abbreviating
        """
        if not self.enabled:
            return
            
        self.nodes_skipped += 1
        self.skipped_nodes.append((node.__class__.__name__, depth, reason))
    
    def print_summary(self) -> None:
        """Print a summary of debug information if enabled."""
        if not self.enabled:
            return
            
        print("\n----- Debug Summary -----")
        print(f"Nodes considered: {self.nodes_considered}")
        print(f"Nodes abbreviated: {self.nodes_abbreviated}")
        print(f"Nodes skipped: {self.nodes_skipped}")
        print(f"Total characters saved: {self.chars_saved}")
        print(f"Maximum depth reached: {self.max_depth_reached}")
        
        print("\nDepth distribution:")
        for depth in sorted(self.depth_counts.keys()):
            print(f"  Depth {depth}: {self.depth_counts[depth]} nodes")
        
        if self.abbreviated_nodes:
            print("\nAbbreviated nodes:")
            for node_type, depth, chars_saved in self.abbreviated_nodes:
                print(f"  {node_type} at depth {depth} (saved {chars_saved} chars)")
        
        if self.skipped_nodes:
            print("\nSkipped nodes:")
            for node_type, depth, reason in self.skipped_nodes:
                print(f"  {node_type} at depth {depth} - {reason}")
        
        if not self.abbreviated_nodes and not self.skipped_nodes:
            print("\nNo nodes were abbreviated. Try:")
            print("  1. Decreasing the --depth parameter")
            print("  2. Using a file with deeper nesting")
        
        print("------------------------\n")


class CodeAbbreviator(cst.CSTTransformer):
    """
    A transformer that abbreviates nested code blocks beyond a specified depth.
    
    This replaces deeply nested code with an ellipsis comment and a pass statement
    to maintain syntactic correctness, but only if doing so reduces the character count.
    """
    
    METADATA_DEPENDENCIES = (ParentNodeProvider, PositionProvider)
    
    def __init__(self, max_depth: int = 2, debug_info: Optional[DebugInfo] = None):
        """
        Initialize the CodeAbbreviator.
        
        Args:
            max_depth: Maximum nesting depth to preserve (default: 2)
            debug_info: Debug information collector
        """
        super().__init__()
        self.max_depth = max_depth
        self.current_depth = 0
        self.stack = []
        self.debug_info = debug_info or DebugInfo()
    
    def _should_consider_abbreviation(self, node: cst.CSTNode) -> bool:
        """
        Determine if the current node should be considered for abbreviation based on depth.
        
        Args:
            node: The node to check
        
        Returns:
            True if the node should be considered for abbreviation, False otherwise
        """
        return self.current_depth > self.max_depth
    
    def _get_ellipsis_comment(self) -> cst.EmptyLine:
        """
        Create an ellipsis comment for abbreviated code.
        
        Returns:
            An EmptyLine node with a trailing comment containing ellipsis
        """
        return cst.EmptyLine(
            indent=True,
            comment=cst.Comment(value="# ...")
        )
    
    def _get_pass_statement(self) -> cst.SimpleStatementLine:
        """
        Create a pass statement for abbreviated code.
        
        Returns:
            A SimpleStatementLine containing a Pass node
        """
        return cst.SimpleStatementLine(
            body=[cst.Pass()],
        )
    
    def _create_abbreviated_block(self) -> cst.IndentedBlock:
        """
        Create an abbreviated indented block.
        
        Returns:
            An IndentedBlock containing an ellipsis comment and a pass statement
        """
        return cst.IndentedBlock(
            body=[
                self._get_ellipsis_comment(),
                self._get_pass_statement()
            ]
        )
    
    def _is_abbreviation_beneficial(self, original_node: cst.CSTNode, abbreviated_node: cst.CSTNode) -> Tuple[bool, int]:
        """
        Check if abbreviating a node actually reduces its character count.
        
        Args:
            original_node: The original node
            abbreviated_node: The abbreviated version of the node
            
        Returns:
            Tuple[bool, int]: A tuple of (is_beneficial, chars_saved)
        """
        original_code = cst.Module([]).code_for_node(original_node)
        abbreviated_code = cst.Module([]).code_for_node(abbreviated_node)
        
        chars_saved = len(original_code) - len(abbreviated_code)
        return chars_saved > 0, chars_saved
    
    def visit_FunctionDef(self, node: cst.FunctionDef) -> Optional[bool]:
        """
        Visit a function definition node and track depth.
        
        Args:
            node: The FunctionDef node being visited
            
        Returns:
            Optional[bool]: Whether to continue traversal
        """
        self.current_depth += 1
        self.stack.append(node)
        self.debug_info.consider_node(node, self.current_depth)
        return not self._should_consider_abbreviation(node)
    
    def leave_FunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        """
        Leave a function definition node and potentially abbreviate its body.
        
        Args:
            original_node: The original FunctionDef node
            updated_node: The updated FunctionDef node
            
        Returns:
            cst.FunctionDef: The potentially modified FunctionDef node
        """
        result = updated_node
        
        if self._should_consider_abbreviation(original_node):
            # Create an abbreviated version of this function
            abbreviated_node = updated_node.with_changes(
                body=self._create_abbreviated_block()
            )
            
            # Check if abbreviation actually saves characters
            is_beneficial, chars_saved = self._is_abbreviation_beneficial(updated_node, abbreviated_node)
            
            if is_beneficial:
                result = abbreviated_node
                self.debug_info.abbreviate_node(original_node, self.current_depth, chars_saved)
            else:
                self.debug_info.skip_node(original_node, self.current_depth, "No character reduction")
        
        self.current_depth -= 1
        self.stack.pop()
        return result
    
    def visit_ClassDef(self, node: cst.ClassDef) -> Optional[bool]:
        """
        Visit a class definition node and track depth.
        
        Args:
            node: The ClassDef node being visited
            
        Returns:
            Optional[bool]: Whether to continue traversal
        """
        self.current_depth += 1
        self.stack.append(node)
        self.debug_info.consider_node(node, self.current_depth)
        return not self._should_consider_abbreviation(node)
    
    def leave_ClassDef(
        self, original_node: cst.ClassDef, updated_node: cst.ClassDef
    ) -> cst.ClassDef:
        """
        Leave a class definition node and potentially abbreviate its body.
        
        Args:
            original_node: The original ClassDef node
            updated_node: The updated ClassDef node
            
        Returns:
            cst.ClassDef: The potentially modified ClassDef node
        """
        result = updated_node
        
        if self._should_consider_abbreviation(original_node):
            # Create an abbreviated version of this class
            abbreviated_node = updated_node.with_changes(
                body=self._create_abbreviated_block()
            )
            
            # Check if abbreviation actually saves characters
            is_beneficial, chars_saved = self._is_abbreviation_beneficial(updated_node, abbreviated_node)
            
            if is_beneficial:
                result = abbreviated_node
                self.debug_info.abbreviate_node(original_node, self.current_depth, chars_saved)
            else:
                self.debug_info.skip_node(original_node, self.current_depth, "No character reduction")
        
        self.current_depth -= 1
        self.stack.pop()
        return result
    
    def visit_If(self, node: cst.If) -> Optional[bool]:
        """
        Visit an if statement node and track depth.
        
        Args:
            node: The If node being visited
            
        Returns:
            Optional[bool]: Whether to continue traversal
        """
        self.current_depth += 1
        self.stack.append(node)
        self.debug_info.consider_node(node, self.current_depth)
        return not self._should_consider_abbreviation(node)
    
    def leave_If(
        self, original_node: cst.If, updated_node: cst.If
    ) -> cst.If:
        """
        Leave an if statement node and potentially abbreviate its body.
        
        Args:
            original_node: The original If node
            updated_node: The updated If node
            
        Returns:
            cst.If: The potentially modified If node
        """
        result = updated_node
        
        if self._should_consider_abbreviation(original_node):
            # Create an abbreviated version of this if statement
            abbreviated_node = updated_node.with_changes(
                body=self._create_abbreviated_block()
            )
            
            # If there's an else clause, abbreviate that too
            if updated_node.orelse:
                if isinstance(updated_node.orelse, cst.Else):
                    abbreviated_node = abbreviated_node.with_changes(
                        orelse=updated_node.orelse.with_changes(
                            body=self._create_abbreviated_block()
                        )
                    )
                else:
                    # Handle elif chains by converting them to a simple else
                    abbreviated_node = abbreviated_node.with_changes(
                        orelse=cst.Else(
                            body=self._create_abbreviated_block()
                        )
                    )
            
            # Check if abbreviation actually saves characters
            is_beneficial, chars_saved = self._is_abbreviation_beneficial(updated_node, abbreviated_node)
            
            if is_beneficial:
                result = abbreviated_node
                self.debug_info.abbreviate_node(original_node, self.current_depth, chars_saved)
            else:
                self.debug_info.skip_node(original_node, self.current_depth, "No character reduction")
        
        self.current_depth -= 1
        self.stack.pop()
        return result
    
    def visit_While(self, node: cst.While) -> Optional[bool]:
        """
        Visit a while loop node and track depth.
        
        Args:
            node: The While node being visited
            
        Returns:
            Optional[bool]: Whether to continue traversal
        """
        self.current_depth += 1
        self.stack.append(node)
        self.debug_info.consider_node(node, self.current_depth)
        return not self._should_consider_abbreviation(node)
    
    def leave_While(
        self, original_node: cst.While, updated_node: cst.While
    ) -> cst.While:
        """
        Leave a while loop node and potentially abbreviate its body.
        
        Args:
            original_node: The original While node
            updated_node: The updated While node
            
        Returns:
            cst.While: The potentially modified While node
        """
        result = updated_node
        
        if self._should_consider_abbreviation(original_node):
            # Create an abbreviated version of this while loop
            abbreviated_node = updated_node.with_changes(
                body=self._create_abbreviated_block()
            )
            
            # If there's an else clause, abbreviate that too
            if updated_node.orelse:
                abbreviated_node = abbreviated_node.with_changes(
                    orelse=updated_node.orelse.with_changes(
                        body=self._create_abbreviated_block()
                    )
                )
            
            # Check if abbreviation actually saves characters
            is_beneficial, chars_saved = self._is_abbreviation_beneficial(updated_node, abbreviated_node)
            
            if is_beneficial:
                result = abbreviated_node
                self.debug_info.abbreviate_node(original_node, self.current_depth, chars_saved)
            else:
                self.debug_info.skip_node(original_node, self.current_depth, "No character reduction")
        
        self.current_depth -= 1
        self.stack.pop()
        return result
    
    def visit_For(self, node: cst.For) -> Optional[bool]:
        """
        Visit a for loop node and track depth.
        
        Args:
            node: The For node being visited
            
        Returns:
            Optional[bool]: Whether to continue traversal
        """
        self.current_depth += 1
        self.stack.append(node)
        self.debug_info.consider_node(node, self.current_depth)
        return not self._should_consider_abbreviation(node)
    
    def leave_For(
        self, original_node: cst.For, updated_node: cst.For
    ) -> cst.For:
        """
        Leave a for loop node and potentially abbreviate its body.
        
        Args:
            original_node: The original For node
            updated_node: The updated For node
            
        Returns:
            cst.For: The potentially modified For node
        """
        result = updated_node
        
        if self._should_consider_abbreviation(original_node):
            # Create an abbreviated version of this for loop
            abbreviated_node = updated_node.with_changes(
                body=self._create_abbreviated_block()
            )
            
            # If there's an else clause, abbreviate that too
            if updated_node.orelse:
                abbreviated_node = abbreviated_node.with_changes(
                    orelse=updated_node.orelse.with_changes(
                        body=self._create_abbreviated_block()
                    )
                )
            
            # Check if abbreviation actually saves characters
            is_beneficial, chars_saved = self._is_abbreviation_beneficial(updated_node, abbreviated_node)
            
            if is_beneficial:
                result = abbreviated_node
                self.debug_info.abbreviate_node(original_node, self.current_depth, chars_saved)
            else:
                self.debug_info.skip_node(original_node, self.current_depth, "No character reduction")
        
        self.current_depth -= 1
        self.stack.pop()
        return result
    
    def visit_Try(self, node: cst.Try) -> Optional[bool]:
        """
        Visit a try statement node and track depth.
        
        Args:
            node: The Try node being visited
            
        Returns:
            Optional[bool]: Whether to continue traversal
        """
        self.current_depth += 1
        self.stack.append(node)
        self.debug_info.consider_node(node, self.current_depth)
        return not self._should_consider_abbreviation(node)
    
    def leave_Try(
        self, original_node: cst.Try, updated_node: cst.Try
    ) -> cst.Try:
        """
        Leave a try statement node and potentially abbreviate its body.
        
        Args:
            original_node: The original Try node
            updated_node: The updated Try node
            
        Returns:
            cst.Try: The potentially modified Try node
        """
        result = updated_node
        
        if self._should_consider_abbreviation(original_node):
            # Create an abbreviated version of this try statement
            abbreviated_node = updated_node.with_changes(
                body=self._create_abbreviated_block()
            )
            
            # Abbreviate handlers
            if updated_node.handlers:
                handlers = []
                for handler in updated_node.handlers:
                    handlers.append(
                        handler.with_changes(
                            body=self._create_abbreviated_block()
                        )
                    )
                abbreviated_node = abbreviated_node.with_changes(handlers=handlers)
            
            # Abbreviate else clause if present
            if updated_node.orelse:
                abbreviated_node = abbreviated_node.with_changes(
                    orelse=updated_node.orelse.with_changes(
                        body=self._create_abbreviated_block()
                    )
                )
            
            # Abbreviate finally clause if present
            if updated_node.finalbody:
                abbreviated_node = abbreviated_node.with_changes(
                    finalbody=self._create_abbreviated_block()
                )
            
            # Check if abbreviation actually saves characters
            is_beneficial, chars_saved = self._is_abbreviation_beneficial(updated_node, abbreviated_node)
            
            if is_beneficial:
                result = abbreviated_node
                self.debug_info.abbreviate_node(original_node, self.current_depth, chars_saved)
            else:
                self.debug_info.skip_node(original_node, self.current_depth, "No character reduction")
        
        self.current_depth -= 1
        self.stack.pop()
        return result
    
    def visit_With(self, node: cst.With) -> Optional[bool]:
        """
        Visit a with statement node and track depth.
        
        Args:
            node: The With node being visited
            
        Returns:
            Optional[bool]: Whether to continue traversal
        """
        self.current_depth += 1
        self.stack.append(node)
        self.debug_info.consider_node(node, self.current_depth)
        return not self._should_consider_abbreviation(node)
    
    def leave_With(
        self, original_node: cst.With, updated_node: cst.With
    ) -> cst.With:
        """
        Leave a with statement node and potentially abbreviate its body.
        
        Args:
            original_node: The original With node
            updated_node: The updated With node
            
        Returns:
            cst.With: The potentially modified With node
        """
        result = updated_node
        
        if self._should_consider_abbreviation(original_node):
            # Create an abbreviated version of this with statement
            abbreviated_node = updated_node.with_changes(
                body=self._create_abbreviated_block()
            )
            
            # Check if abbreviation actually saves characters
            is_beneficial, chars_saved = self._is_abbreviation_beneficial(updated_node, abbreviated_node)
            
            if is_beneficial:
                result = abbreviated_node
                self.debug_info.abbreviate_node(original_node, self.current_depth, chars_saved)
            else:
                self.debug_info.skip_node(original_node, self.current_depth, "No character reduction")
        
        self.current_depth -= 1
        self.stack.pop()
        return result


def abbreviate_code(code: str, max_depth: int = 2, debug: bool = False) -> str:
    """
    Parse code and abbreviate nested blocks beyond max_depth if it reduces char count.
    
    Args:
        code: The Python code to abbreviate
        max_depth: Maximum nesting depth to preserve (default: 2)
        debug: Whether to print debug information
        
    Returns:
        str: The abbreviated code
    """
    try:
        # Set up debug info collector
        debug_info = DebugInfo(enabled=debug)
        
        # Parse the code into a CST
        module = cst.parse_module(code)
        
        # Apply our transformer to abbreviate deeply nested code
        transformer = CodeAbbreviator(max_depth=max_depth, debug_info=debug_info)
        modified_module = module.visit(transformer)
        
        # Print debug information if requested
        debug_info.print_summary()
        
        # Generate the abbreviated code
        return modified_module.code
    except Exception as e:
        print(f"Error abbreviating code: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return code


def main():
    """
    Main entry point for the script.
    """
    parser = argparse.ArgumentParser(
        description="Abbreviate nested Python code beyond a specified depth if it reduces character count."
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default=__file__,
        help="Path to the Python file to abbreviate (default: this script)"
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Maximum nesting depth to preserve (default: 2)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output"
    )
    args = parser.parse_args()
    
    # Read the input file
    with open(args.input_file, "r", encoding="utf-8") as f:
        code = f.read()
    
    # Abbreviate the code
    abbreviated_code = abbreviate_code(code, args.depth, args.debug)
    
    # Generate the output file name
    base_name, ext = os.path.splitext(args.input_file)
    output_file = f"{base_name}.abbreviated{ext}"
    
    # Write the abbreviated code to the output file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(abbreviated_code)
    
    print(f"Abbreviated code written to {output_file}")
    
    # Show character count comparison
    original_chars = len(code)
    abbreviated_chars = len(abbreviated_code)
    chars_saved = original_chars - abbreviated_chars
    percent_saved = (chars_saved / original_chars) * 100 if original_chars > 0 else 0
    
    print(f"Original file: {original_chars} characters")
    print(f"Abbreviated file: {abbreviated_chars} characters")
    print(f"Characters saved: {chars_saved} ({percent_saved:.2f}%)")


# Add some deeply nested code to ensure something will be abbreviated
# when the script is run on itself
def example_of_deep_nesting():
    """An example of deeply nested code that should be abbreviated."""
    def level_1():
        """First level of nesting."""
        def level_2():
            """Second level of nesting."""
            def level_3():
                """Third level of nesting."""
                def level_4():
                    """Fourth level of nesting."""
                    def level_5():
                        """Fifth level of nesting."""
                        print("This is very deeply nested")
                        
                        if True:
                            print("Even deeper nesting")
                            
                            for i in range(10):
                                print(f"Nested loop at iteration {i}")
                                
                                while i < 5:
                                    print("This will never be seen when abbreviated")
                                    i += 1
                    
                    level_5()
                
                level_4()
            
            level_3()
        
        level_2()
    
    # Another example using different types of control structures
    if True:
        if True:
            if True:
                if True:
                    print("Deeply nested if statements")
                    
                    try:
                        something = 1 / 0
                    except ZeroDivisionError:
                        print("Caught exception in deeply nested code")
                        
                        with open(__file__, "r") as f:
                            contents = f.read()
                            print(f"File has {len(contents)} characters")


if __name__ == "__main__":
    main()