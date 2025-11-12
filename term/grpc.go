// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
// Author: Nicolas Tran
//
// This file is part of SpecMon.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with program. If not, see <https://www.gnu.org/licenses/>.

package term

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/jhump/protoreflect/v2/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

func handleGrpcFunction(f *Function, args []Term, modified bool) (Term, error) {
	if len(f.Args) != QuaternaryArity {
		return nil, ErrQuaternaryArity
	}

	// read parameters
	server := args[0]
	serviceName := args[1]
	requestName := args[2]

	// dts = data to send
	dts, err := AsBytes(args[3])
	if err != nil {
		if modified {
			return NewFunction(f.Name, args), nil
		}
		return f, nil
	}

	log.Printf("server: %s, service: %s, request: %s", server, serviceName, requestName)

	// we need the type conversion to get real string via Value;
	// if we user String(), the string is wrapped with ''
	serverConstant, ok := server.(*Constant[string])
	if !ok {
		panic("error during type conversion of grpc server")
	}

	serviceNameConstant, ok := serviceName.(*Constant[string])
	if !ok {
		panic("error during type conversion of grpc service name")
	}

	requestNameConstant, ok := requestName.(*Constant[string])
	if !ok {
		panic("error during type conversion of grpc request name")
	}

	grpcResult, err := grpcCall(serverConstant.Value, serviceNameConstant.Value, requestNameConstant.Value, dts)
	if err != nil {
		return nil, fmt.Errorf("grpc call failed: %w", err)
	}
	res, err := grpcMessageToFunction(grpcResult)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func grpcCall(server string, serviceName string, methodName string, data []uint8) (*dynamicpb.Message, error) {
	ctx := context.Background()

	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.NewClient(server, opts...)
	if err != nil {
		return nil, fmt.Errorf("could not establish connection: %w", err)
	}
	defer conn.Close()

	reflectClient := grpcreflect.NewClientAuto(ctx, conn)

	resolver := reflectClient.AsResolver()
	svcDescGen, err := resolver.FindDescriptorByName(protoreflect.FullName(serviceName))
	if err != nil {
		panic("could not find service descriptor")
	}

	svcDesc, ok := svcDescGen.(protoreflect.ServiceDescriptor)
	if !ok {
		panic("found descriptor is not a service descriptor")
	}

	methodDesc := svcDesc.Methods().ByName(protoreflect.Name(methodName))
	if methodDesc == nil {
		panic(fmt.Sprintf("Unable to find method name %s", methodName))
	}

	request := dynamicpb.NewMessage(methodDesc.Input())
	response := dynamicpb.NewMessage(methodDesc.Output())

	request.Set(methodDesc.Input().Fields().ByName("data"), protoreflect.ValueOf(data))

	methodString := fmt.Sprintf("/%s/%s", svcDesc.FullName(), methodDesc.Name())

	err = conn.Invoke(ctx, methodString, request, response)
	if err != nil {
		return nil, fmt.Errorf("rpc call failed: %w", err)
	}

	return response, nil
}

func grpcMessageToFunction(dynMsg *dynamicpb.Message) (*Function, error) {
	if dynMsg == nil {
		return nil, errors.New("unexpected: dynMsg is nil")
	}

	var numFields int
	var singleFieldDesc protoreflect.FieldDescriptor
	var singleFieldValue protoreflect.Value

	fields := dynMsg.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fieldDesc := fields.Get(i)
		if dynMsg.Has(fieldDesc) {
			numFields++
			singleFieldDesc = fieldDesc
			singleFieldValue = dynMsg.Get(fieldDesc)
		}
	}

	if numFields == 1 && singleFieldDesc.Kind() == protoreflect.MessageKind && !singleFieldDesc.IsList() {
		fieldName := string(singleFieldDesc.Name())

		msg, ok := singleFieldValue.Message().Interface().(*dynamicpb.Message)
		if !ok {
			return nil, errors.New("internal error: field kind was message, but type assertion failed")
		}

		parsed, err := grpcMessageToFunction(msg)
		if err != nil {
			return nil, err
		}

		keyValuePair := NewFunction("pair", make([]Term, 2))
		keyValuePair.Args[0] = NewConstant[string](fieldName)
		keyValuePair.Args[1] = parsed
		return keyValuePair, nil
	}

	resultArgs := make([]Term, 0, numFields)
	for i := 0; i < fields.Len(); i++ {
		fieldDesc := fields.Get(i)
		if !dynMsg.Has(fieldDesc) {
			continue
		}

		fieldName := string(fieldDesc.Name())
		value := dynMsg.Get(fieldDesc)
		var resPair *Function

		switch {
		case fieldDesc.IsList():
			list := value.List()
			listPair := NewFunction("pair", make([]Term, list.Len()))
			for j := 0; j < list.Len(); j++ {
				item := list.Get(j)
				if msg, ok := item.Message().Interface().(*dynamicpb.Message); ok {
					r, err := grpcMessageToFunction(msg)
					if err != nil {
						return nil, err
					}
					listPair.Args[j] = r
				} else {
					panic("unhandled type in a repeated field")
				}
			}
			resPair = NewFunction("pair", make([]Term, 2))
			resPair.Args[0] = NewConstant[string](fieldName)
			resPair.Args[1] = listPair

		case fieldDesc.Kind() == protoreflect.BytesKind:
			resPair = NewFunction("pair", make([]Term, 2))
			resPair.Args[0] = NewConstant[string](fieldName)
			// This is the correct and simple way to get the byte slice.
			// The previous complex logic with proto.Clone was incorrect.
			resPair.Args[1] = NewConstant[[]byte](value.Bytes())

		case fieldDesc.Kind() == protoreflect.MessageKind:
			msg := value.Message().Interface().(*dynamicpb.Message)
			parsedMsg, err := grpcMessageToFunction(msg)
			if err != nil {
				return nil, err
			}
			resPair = NewFunction("pair", make([]Term, 2))
			resPair.Args[0] = NewConstant[string](fieldName)
			resPair.Args[1] = parsedMsg

		case fieldDesc.Kind() == protoreflect.StringKind:
			resPair = NewFunction("pair", make([]Term, 2))
			resPair.Args[0] = NewConstant[string](fieldName)
			resPair.Args[1] = NewConstant[string](value.String())

		default:
			panic(fmt.Sprintf("unhandled kind in grpcMessageToFunction: %v", fieldDesc.Kind()))
		}
		resultArgs = append(resultArgs, resPair)
	}

	resultFunction := NewFunction("pair", resultArgs)
	return resultFunction, nil
}
